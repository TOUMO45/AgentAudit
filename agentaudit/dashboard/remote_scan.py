"""Live scan of a *public GitHub repo* — a new, untrusted attack surface.

This module is deliberately narrow. It takes one ``https://github.com/<owner>/<repo>``
URL, shallow-clones it into a throwaway temp directory, runs the **existing**
Layer 2 static analyzer against the source, and returns findings in exactly the
schema :class:`agentaudit.dashboard.backend.ScanRecord` already produces for
local fixtures. Then it deletes the clone.

Security posture (mirrors the hard rules the feature was built under):

* **Never executes fetched code.** The only thing done with the cloned source is
  :func:`ast.parse` via :mod:`agentaudit.layers.static_graph` /
  :mod:`agentaudit.layers.capability_graph`. This module never imports
  :mod:`agentaudit.audit` / ``run_audit`` (which would import the target through
  the rug-pull layer), and contains no ``exec`` / ``eval`` / ``importlib`` /
  ``pip`` / ``setup.py`` path.
* **Never runs repo-provided install steps.** Exactly three git subcommands run
  (``clone``, optional ``fetch``, optional ``checkout``); nothing else.
* **Strict input validation** — :func:`parse_github_target` accepts only a
  well-formed github.com URL (optionally ``/tree/<ref>`` or ``/commit/<ref>``).
* **Hard resource limits** — pre-clone size cap via the GitHub API, post-clone
  byte cap, per-file byte cap, and wall-clock timeouts on both clone and scan.
* **Isolated temp dir per request**, always removed in a ``finally`` block.
* **Single-flight** — an in-process lock; concurrent calls get :class:`ScanBusy`.
* **No path traversal from repo filenames** — symlinks and any path escaping the
  clone root are skipped; finding locations are rewritten to ``<owner>/<repo>``
  relative form before they leave this module.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from re import compile as _rx

from agentaudit.layers import static_graph
from agentaudit.layers import harness_integrity
from agentaudit.layers.capability_graph import analyze_capability_pairs
from agentaudit.models import Layer, LayerReport
from agentaudit.scorer import score_findings

# --------------------------------------------------------------------------- #
# Tunables (all deliberately conservative — this is a demo-scale safeguard).
# --------------------------------------------------------------------------- #
MAX_URL_LEN = 400
MAX_REPO_KB = 200 * 1024          # 200 MiB, measured by the GitHub API `size`
MAX_TREE_BYTES = 200 * 1024 * 1024  # 200 MiB, measured on the actual checkout
MAX_PY_FILE_BYTES = 1_500_000     # skip any single .py bigger than this
CLONE_TIMEOUT_S = 60             # wall-clock budget for clone (+ ref fetch)
SCAN_TIMEOUT_S = 30             # wall-clock budget for the AST scan loop
API_TIMEOUT_S = 10
_TMP_PREFIX = "agentaudit-remote-"

# Single-flight: only one remote scan may run in this process at a time
# (the dashboard server is threaded, so concurrent POSTs are real).
_SCAN_LOCK = threading.Lock()

_SKIP_DIRS = {".git", ".venv", "venv", "env", "site-packages", "node_modules",
              "__pycache__", ".tox", ".mypy_cache", "dist", "build"}


# --------------------------------------------------------------------------- #
# Error taxonomy — every distinct failure the UI must show a distinct message
# for is its own class with an HTTP status and a short machine `code`.
# --------------------------------------------------------------------------- #
class RemoteScanError(Exception):
    """Base class for every expected (non-bug) remote-scan failure."""

    code = "error"
    http_status = 400


class InvalidRepoURL(RemoteScanError):
    code = "invalid_url"
    http_status = 400


class RepoNotFound(RemoteScanError):
    code = "not_found"
    http_status = 404


class RepoTooLarge(RemoteScanError):
    code = "too_large"
    http_status = 400


class CloneFailed(RemoteScanError):
    code = "clone_failed"
    http_status = 502


class ScanTimeout(RemoteScanError):
    code = "timeout"
    http_status = 504


class NoStrandsCode(RemoteScanError):
    code = "no_strands_code"
    http_status = 400


class ScanBusy(RemoteScanError):
    code = "busy"
    http_status = 429


# --------------------------------------------------------------------------- #
# Rule 3 — input validation
# --------------------------------------------------------------------------- #
# GitHub owner: 1-39 chars, alphanumeric or single hyphens, cannot start/end
# with a hyphen (we enforce "not start" here; a trailing hyphen just fails the
# real clone, which is fine). Repo: 1-100 chars of [A-Za-z0-9._-].
_GITHUB_URL_RE = _rx(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?"
    r"(?:/(?:tree|commit)/(?P<ref>[A-Za-z0-9][A-Za-z0-9._/-]{0,127}))?"
    r"/?$"
)
_REF_RE = _rx(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_HEX40_RE = _rx(r"^[0-9a-fA-F]{7,40}$")


class GitHubTarget:
    """A validated, *reconstructed* clone target — never carries raw input."""

    __slots__ = ("owner", "repo", "ref", "clone_url", "display")

    def __init__(self, owner: str, repo: str, ref: str | None):
        self.owner = owner
        self.repo = repo
        self.ref = ref
        # Always rebuilt from the validated parts, never echoed from input.
        self.clone_url = f"https://github.com/{owner}/{repo}.git"
        short = ref[:7] if (ref and _HEX40_RE.match(ref)) else ref
        self.display = f"github.com/{owner}/{repo}" + (f"@{short}" if short else "")


def parse_github_target(raw: str) -> GitHubTarget:
    """Accept *only* a well-formed public github.com repo URL.

    Rejects: non-strings, over-long input, any non-``https`` scheme, any host
    that is not exactly ``github.com``, embedded credentials, non-standard
    ports, ``..`` path traversal, and anything the strict regex does not match.
    """
    if not isinstance(raw, str):
        raise InvalidRepoURL("URL must be a string.")
    raw = raw.strip()
    if not raw:
        raise InvalidRepoURL("No URL provided.")
    if len(raw) > MAX_URL_LEN:
        raise InvalidRepoURL("URL is unreasonably long.")
    if any(c in raw for c in ("\n", "\r", "\t", " ", "\x00")):
        raise InvalidRepoURL("URL contains whitespace or control characters.")

    m = _GITHUB_URL_RE.match(raw)
    if not m:
        raise InvalidRepoURL(
            "Not a valid public GitHub repository URL. "
            "Expected https://github.com/<owner>/<repo>."
        )

    # Defence in depth: an independent structural check via urlsplit.
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme != "https":
        raise InvalidRepoURL("Only https:// GitHub URLs are accepted.")
    if (parts.hostname or "").lower() != "github.com":
        raise InvalidRepoURL("Host must be exactly github.com.")
    if parts.port not in (None, 443):
        raise InvalidRepoURL("Non-standard ports are not allowed.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise InvalidRepoURL("Credentials in the URL are not allowed.")

    owner = m.group("owner")
    repo = m.group("repo")
    ref = m.group("ref")

    if repo in (".", ".."):
        raise InvalidRepoURL("Invalid repository name.")
    if ".." in raw:
        raise InvalidRepoURL("Path traversal ('..') is not allowed.")
    if ref is not None:
        if not _REF_RE.match(ref) or ".." in ref or ref.startswith("-") or ref.endswith("/"):
            raise InvalidRepoURL("Invalid branch/commit reference.")

    return GitHubTarget(owner, repo, ref)


# --------------------------------------------------------------------------- #
# Rule 4 (pre) — size gate via the GitHub API (constant host, no user host)
# --------------------------------------------------------------------------- #
def _precheck_repo_size(t: GitHubTarget) -> str | None:
    """Reject an over-cap / private / missing repo. Returns the repo's SPDX
    license id (e.g. ``"Apache-2.0"``) when the GitHub API reports one, else
    ``None`` — used only for provenance in the scan record, never for a gate."""
    api = f"https://api.github.com/repos/{t.owner}/{t.repo}"
    req = urllib.request.Request(  # noqa: S310 - constant https host
        api,
        headers={
            "User-Agent": "agentaudit-remote-scan",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT_S) as resp:  # noqa: S310
            data = json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code in (404, 451):
            raise RepoNotFound("Repository not found (or not public).") from None
        # Rate-limited / transient — fall through to the post-clone byte cap.
        return None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None  # network hiccup: the post-clone cap is the backstop

    if data.get("private") is True:
        raise RepoNotFound("Repository is private.")
    size_kb = data.get("size")
    if isinstance(size_kb, (int, float)) and size_kb > MAX_REPO_KB:
        raise RepoTooLarge(
            f"Repository is ~{size_kb / 1024:.0f} MB, over the "
            f"{MAX_REPO_KB // 1024} MB limit for remote scans."
        )
    lic = (data.get("license") or {}).get("spdx_id")
    return lic if lic and lic != "NOASSERTION" else None


# --------------------------------------------------------------------------- #
# Rules 1/2/4 — git clone, hardened
# --------------------------------------------------------------------------- #
def _git_base_env() -> dict:
    env = dict(os.environ)
    env.update(
        GIT_TERMINAL_PROMPT="0",   # never block on a credential prompt
        GIT_ASKPASS="",
        GIT_CONFIG_NOSYSTEM="1",
        GCM_INTERACTIVE="never",
    )
    return env


# Config flags applied to every git call: no hooks, no local/ext transports.
_GIT_HARDEN = [
    "-c", "core.hooksPath=",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "credential.helper=",
]


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Kill ``proc`` *and every child it spawned*.

    ``git clone`` forks helpers (``git-remote-https``, ``index-pack``); a plain
    ``proc.kill()`` leaves those running and holding the pipe/temp-dir handles,
    so a hung clone would block us for the full natural clone time. This kills
    the whole tree so the wall-clock budget is actually honoured.
    """
    try:
        if os.name == "nt":
            subprocess.run(  # noqa: S603,S607
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=10, check=False,
            )
        else:
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
    except Exception:  # noqa: BLE001 - best-effort teardown
        try:
            proc.kill()
        except Exception:
            pass


def _run_git(args: list[str], *, timeout: float, cwd: str | None = None) -> subprocess.CompletedProcess:
    timeout = max(1.0, timeout)
    kw: dict = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True  # own process group -> killpg works
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, validated inputs
        ["git", *_GIT_HARDEN, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_git_base_env(),
        cwd=cwd,
        **kw,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_tree(proc)
        try:
            proc.communicate(timeout=10)  # reap; bounded grace period
        except subprocess.TimeoutExpired:
            pass
        raise
    return subprocess.CompletedProcess(proc.args, proc.returncode or 0, out, err)


def _git_clone(t: GitHubTarget, dest: str, *, deadline: float) -> None:
    """Shallow-clone ``t`` into ``dest``. Raises on timeout or git failure."""
    try:
        r = _run_git(
            ["clone", "--depth", "1", "--no-recurse-submodules", "--no-tags",
             "--quiet", "--", t.clone_url, dest],
            timeout=deadline - time.monotonic(),
            cwd=os.path.dirname(dest),
        )
    except subprocess.TimeoutExpired:
        raise ScanTimeout(
            f"Clone exceeded the {CLONE_TIMEOUT_S}s budget and was aborted."
        ) from None
    if r.returncode != 0:
        raise CloneFailed(f"git clone failed: {_tail(r.stderr)}")

    if t.ref:
        try:
            f = _run_git(
                ["-C", dest, "fetch", "--depth", "1", "--no-tags", "origin", "--", t.ref],
                timeout=deadline - time.monotonic(),
            )
        except subprocess.TimeoutExpired:
            raise ScanTimeout(
                f"Fetching ref exceeded the {CLONE_TIMEOUT_S}s budget."
            ) from None
        if f.returncode != 0:
            raise CloneFailed(f"branch/commit '{t.ref}' not found: {_tail(f.stderr)}")
        try:
            c = _run_git(
                ["-C", dest, "checkout", "--detach", "--force", "FETCH_HEAD"],
                timeout=deadline - time.monotonic(),
            )
        except subprocess.TimeoutExpired:
            raise ScanTimeout("Checkout exceeded the time budget.") from None
        if c.returncode != 0:
            raise CloneFailed(f"could not check out '{t.ref}': {_tail(c.stderr)}")


def _tail(s: str, n: int = 240) -> str:
    s = (s or "").strip().replace("\n", " ")
    return s[-n:]


# --------------------------------------------------------------------------- #
# Rule 4 (post) — the checkout must not exceed the byte cap
# --------------------------------------------------------------------------- #
def _enforce_tree_size(root: str) -> None:
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # do not descend into the .git dir for the size check either
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                if os.path.islink(fp):
                    continue
                total += os.path.getsize(fp)
            except OSError:
                continue
            if total > MAX_TREE_BYTES:
                raise RepoTooLarge(
                    f"Checked-out tree exceeds the {MAX_TREE_BYTES // (1024 * 1024)} MB "
                    f"limit for remote scans."
                )


# --------------------------------------------------------------------------- #
# Rules 1/7 — the scan itself (AST only, no execution, no path escape)
# --------------------------------------------------------------------------- #
def _looks_like_strands_agent(text: str) -> bool:
    return (("from strands import" in text) or ("import strands" in text)) and ("@tool" in text)


def _iter_python_files(root: Path):
    """Yield real .py files strictly inside ``root`` (no symlinks, no escapes)."""
    root_res = root.resolve()
    for p in sorted(root.rglob("*.py")):
        if p.is_symlink():
            continue
        if _SKIP_DIRS & set(p.relative_to(root).parts[:-1]):
            continue
        try:
            rp = p.resolve()
        except OSError:
            continue
        try:
            inside = rp.is_relative_to(root_res)
        except ValueError:
            inside = False
        if not inside:
            continue  # symlink or junction escaping the clone root
        yield p, rp.relative_to(root_res).as_posix()


def _scan_tree(root: str, target: GitHubTarget, *, deadline: float) -> tuple[list, dict]:
    findings: list = []
    stats = {"py_files": 0, "strands_files": 0, "parsed": 0, "syntax_errors": 0, "too_big": 0}
    root_path = Path(root)

    for path, rel in _iter_python_files(root_path):
        if time.monotonic() > deadline:
            raise ScanTimeout(
                f"Scan exceeded the {SCAN_TIMEOUT_S}s budget and was aborted."
            )
        stats["py_files"] += 1
        try:
            if path.stat().st_size > MAX_PY_FILE_BYTES:
                stats["too_big"] += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _looks_like_strands_agent(text):
            continue
        stats["strands_files"] += 1

        try:
            fs = static_graph.analyze(str(path))
            fs += analyze_capability_pairs(str(path))
            fs += harness_integrity.analyze(str(path))
        except (SyntaxError, ValueError, UnicodeDecodeError, RecursionError):
            stats["syntax_errors"] += 1
            continue
        stats["parsed"] += 1

        display_path = f"{target.owner}/{target.repo}/{rel}"
        for f in fs:
            f.file = display_path
            f.fingerprint = f"{f.detector}:{display_path}:{f.line}"
        findings.extend(fs)

    return findings, stats


# --------------------------------------------------------------------------- #
# Rule 5 — cleanup that survives Windows read-only .git objects
# --------------------------------------------------------------------------- #
def _rmtree_robust(path: str) -> None:
    if not path or not os.path.exists(path):
        return

    def _retry(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    try:
        shutil.rmtree(path, onexc=_retry)  # py311+: onexc
    except TypeError:  # pragma: no cover - very old python
        shutil.rmtree(path, onerror=lambda f, t, e: _retry(f, t, e))
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def scan_remote_repo(raw_url: str) -> dict:
    """Validate, clone, statically scan, and clean up. Returns a scan record
    in the same schema the dashboard already renders for local fixtures.

    Raises a :class:`RemoteScanError` subclass for every expected failure.
    """
    if not _SCAN_LOCK.acquire(blocking=False):  # rule 6
        raise ScanBusy("Another remote scan is already running — try again shortly.")

    tmp: str | None = None
    t0 = time.monotonic()
    try:
        target = parse_github_target(raw_url)            # rule 3
        license_id = _precheck_repo_size(target)         # rule 4 (pre) + provenance

        tmp = tempfile.mkdtemp(prefix=_TMP_PREFIX)       # rule 5
        dest = os.path.join(tmp, "repo")

        _git_clone(target, dest, deadline=t0 + CLONE_TIMEOUT_S)   # rules 1/2/4
        _enforce_tree_size(dest)                                  # rule 4 (post)

        findings, stats = _scan_tree(                             # rules 1/7
            dest, target, deadline=time.monotonic() + SCAN_TIMEOUT_S
        )

        if stats["strands_files"] == 0:
            raise NoStrandsCode(
                "No Strands agent code found in this repository "
                "(looked for `from strands import …` together with `@tool`)."
            )
        if stats["parsed"] == 0:
            raise NoStrandsCode(
                f"Found {stats['strands_files']} candidate file(s) but none could be "
                f"parsed (syntax errors)."
            )

        dur_ms = int((time.monotonic() - t0) * 1000)
        return _build_record(target, findings, stats, dur_ms, license_id)
    finally:
        _rmtree_robust(tmp)     # rule 5 — always, even on crash/timeout
        _SCAN_LOCK.release()    # rule 6


def _build_record(target: GitHubTarget, findings: list, stats: dict, dur_ms: int,
                  license_id: str | None = None) -> dict:
    """Shape findings exactly like backend.ScanRecord.to_dict()."""
    n_arch = len(findings)
    detail = (
        f"static tool-trust graph on {stats['strands_files']} Strands file(s) "
        f"(of {stats['py_files']} .py scanned): {n_arch} finding(s)"
    )
    if stats["syntax_errors"]:
        detail += f"; {stats['syntax_errors']} file(s) skipped (syntax errors)"
    if stats["too_big"]:
        detail += f"; {stats['too_big']} file(s) skipped (too large)"

    layer_reports = [
        LayerReport(Layer.ARCHITECTURAL, "ran", detail, list(findings)),
        LayerReport(
            Layer.BEHAVIORAL, "skipped",
            "not run for remote repos — no code from a fetched repo is executed "
            "or model-tested (static AST parsing only)",
            [],
        ),
        LayerReport(
            Layer.CLOUD, "skipped",
            "not applicable to a source-only GitHub scan (no deploy config)",
            [],
        ),
    ]

    card = score_findings(target.display, findings, layer_reports, duration_ms=dur_ms)
    return {
        "target": target.display,
        "grade": card.grade,
        "score": card.score,
        "duration_ms": card.duration_ms,
        "generated_at": card.generated_at,
        "counts": card.counts_by_severity(),
        "findings": [f.to_dict() for f in card.findings],
        "layers": [
            {"layer": lr.layer.value, "status": lr.status, "detail": lr.detail}
            for lr in card.layer_reports
        ],
        "policies": [],
        "source": "remote-github",
        "license": license_id,
        "repo_url": f"https://github.com/{target.owner}/{target.repo}"
        + (f"/tree/{target.ref}" if target.ref else ""),
    }
