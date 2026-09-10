"""Security + behavior tests for the public-GitHub-repo remote scan
(``agentaudit.dashboard.remote_scan``).

The offline tests cover every ground rule the feature was built under:
strict URL validation (rule 3), single-flight (rule 6), guaranteed temp-dir
cleanup after a crash or timeout (rule 5), and no path traversal / no
execution of fetched code (rules 1, 7).

The one network test (a real shallow clone of a known repo at a pinned
commit) is opt-in: set ``RUN_REMOTE_INTEGRATION=1`` to run it. It is the
end-to-end proof that the live path reproduces the hand-verified findings in
``references/real_world_findings.md``.
"""

from __future__ import annotations

import glob
import os
import tempfile
import threading

import pytest

from agentaudit.dashboard import remote_scan as rs

# --------------------------------------------------------------------------- #
# Rule 3 — URL validation
# --------------------------------------------------------------------------- #
GOOD = [
    ("https://github.com/kyopark2014/strands-agent",
     ("kyopark2014", "strands-agent", None)),
    ("https://github.com/kyopark2014/strands-agent.git",
     ("kyopark2014", "strands-agent", None)),
    ("https://github.com/strands-agents/samples/",
     ("strands-agents", "samples", None)),
    ("https://github.com/o/r/tree/main",
     ("o", "r", "main")),
    ("https://github.com/o/r/tree/feature/nested-branch",
     ("o", "r", "feature/nested-branch")),
    ("https://github.com/o/r/commit/74af997c3c626fb6ff69359e239c8dde34301c97",
     ("o", "r", "74af997c3c626fb6ff69359e239c8dde34301c97")),
    ("  https://github.com/o/r  ", ("o", "r", None)),  # trimmed
]

BAD = [
    "",
    "not a url",
    "http://github.com/o/r",                       # not https
    "ftp://github.com/o/r",
    "github.com/o/r",                              # no scheme
    "https://github.com/o",                        # no repo
    "https://github.com/",                         # nothing
    "https://raw.githubusercontent.com/o/r/main/x.py",
    "https://github.com.evil.com/o/r",             # look-alike host
    "https://evilgithub.com/o/r",
    "https://github.com@evil.com/o/r",             # netloc confusion
    "https://user:pass@github.com/o/r",            # embedded creds
    "https://github.com:8443/o/r",                 # odd port
    "https://gitlab.com/o/r",
    "git@github.com:o/r.git",                      # scp syntax
    "file:///etc/passwd",
    "https://github.com/../../etc/passwd",
    "https://github.com/o/r/tree/../../../etc",    # traversal in ref
    "https://github.com/o/r/tree/-x",             # option-injection-shaped ref
    "https://github.com/-o/r",                     # owner starts with hyphen
    "https://github.com/o/r ; rm -rf /",          # whitespace / shell metachars
    "https://github.com/o/r%00",                   # NUL
    "https://127.0.0.1/o/r",
    "https://169.254.169.254/o/r",
    "https://localhost/o/r",
    "https://github.com/o/" + "r" * 300,           # absurd repo name
    "x" * 5000,                                    # absurd length
]


@pytest.mark.parametrize("url,expected", GOOD)
def test_parse_accepts_canonical_github_urls(url, expected):
    t = rs.parse_github_target(url)
    assert (t.owner, t.repo, t.ref) == expected
    # clone_url is always reconstructed from validated parts, never echoed
    assert t.clone_url == f"https://github.com/{expected[0]}/{expected[1]}.git"
    assert " " not in t.clone_url


@pytest.mark.parametrize("url", BAD)
def test_parse_rejects_everything_that_is_not_a_plain_github_repo(url):
    with pytest.raises(rs.RemoteScanError):
        rs.parse_github_target(url)


def test_parse_rejects_non_string():
    for bad in (None, 123, b"https://github.com/o/r", ["https://github.com/o/r"]):
        with pytest.raises(rs.InvalidRepoURL):
            rs.parse_github_target(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Rule 5 — the temp dir is always removed, even when the pipeline blows up
# --------------------------------------------------------------------------- #
def _leftover_tmp_dirs():
    return set(glob.glob(os.path.join(tempfile.gettempdir(), rs._TMP_PREFIX + "*")))


def test_crashed_scan_leaves_no_tempdir(monkeypatch):
    before = _leftover_tmp_dirs()

    def boom(target, dest, *, deadline):
        # the temp dir already exists at this point; simulate a mid-clone crash
        assert os.path.isdir(os.path.dirname(dest))
        raise RuntimeError("simulated clone crash")

    monkeypatch.setattr(rs, "_git_clone", boom)
    monkeypatch.setattr(rs, "_precheck_repo_size", lambda t: None)

    with pytest.raises(RuntimeError):
        rs.scan_remote_repo("https://github.com/o/r")

    assert _leftover_tmp_dirs() == before, "temp dir survived a crashed scan"


def test_timed_out_scan_leaves_no_tempdir(monkeypatch):
    before = _leftover_tmp_dirs()

    def slow_clone(target, dest, *, deadline):
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, "agent.py"), "w") as fh:
            fh.write("from strands import tool\n@tool\ndef f():\n    pass\n")
        raise rs.ScanTimeout("Clone exceeded the 60s budget and was aborted.")

    monkeypatch.setattr(rs, "_git_clone", slow_clone)
    monkeypatch.setattr(rs, "_precheck_repo_size", lambda t: None)

    with pytest.raises(rs.ScanTimeout):
        rs.scan_remote_repo("https://github.com/o/r")

    assert _leftover_tmp_dirs() == before, "temp dir survived a timed-out scan"


# --------------------------------------------------------------------------- #
# Rule 6 — single-flight
# --------------------------------------------------------------------------- #
def test_concurrent_scan_is_rejected(monkeypatch):
    monkeypatch.setattr(rs, "_precheck_repo_size", lambda t: None)
    assert rs._SCAN_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(rs.ScanBusy):
            rs.scan_remote_repo("https://github.com/o/r")
    finally:
        rs._SCAN_LOCK.release()


def test_lock_is_released_after_a_failure(monkeypatch):
    monkeypatch.setattr(rs, "_precheck_repo_size", lambda t: None)
    monkeypatch.setattr(rs, "_git_clone",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        rs.scan_remote_repo("https://github.com/o/r")
    # lock must be free again
    assert rs._SCAN_LOCK.acquire(blocking=False)
    rs._SCAN_LOCK.release()


# --------------------------------------------------------------------------- #
# Rules 1 / 7 — scan the tree without executing it or escaping it
# --------------------------------------------------------------------------- #
CLEAN_AGENT = '''\
from strands import Agent, tool

@tool
def get_status(name: str) -> str:
    """read-only status lookup"""
    return {"a": "ok"}.get(name, "unknown")
'''

RCE_AGENT = '''\
from strands import tool
import subprocess

@tool
def bash(command: str) -> str:
    """run a shell command"""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
'''

IMPORT_CRASHES = '''\
from strands import tool
raise SystemExit("this module refuses to be imported")

@tool
def x(command: str):
    __import__("os").system(command)
'''


def _fake_repo(tmp_path, files: dict[str, str]) -> str:
    dest = tmp_path / "repo"
    for rel, content in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return str(dest)


def _patch_clone_with(monkeypatch, dest_builder):
    monkeypatch.setattr(rs, "_precheck_repo_size", lambda t: None)

    def fake_clone(target, dest, *, deadline):
        src = dest_builder()
        os.makedirs(dest, exist_ok=True)
        for root, _dirs, names in os.walk(src):
            for n in names:
                s = os.path.join(root, n)
                rel = os.path.relpath(s, src)
                d = os.path.join(dest, rel)
                os.makedirs(os.path.dirname(d), exist_ok=True)
                with open(s, "rb") as a, open(d, "wb") as b:
                    b.write(a.read())

    monkeypatch.setattr(rs, "_git_clone", fake_clone)


def test_clean_repo_scans_with_zero_or_few_findings(tmp_path, monkeypatch):
    _patch_clone_with(monkeypatch, lambda: _fake_repo(tmp_path, {"agent.py": CLEAN_AGENT}))
    rec = rs.scan_remote_repo("https://github.com/o/clean")
    assert rec["target"] == "github.com/o/clean"
    assert rec["grade"] == "A"
    assert rec["counts"]["critical"] == 0
    # behavioral + cloud layers are explicitly skipped for remote repos
    layers = {l["layer"]: l["status"] for l in rec["layers"]}
    assert layers == {"architectural": "ran", "behavioral": "skipped", "cloud": "skipped"}


def test_findings_never_leak_the_temp_path(tmp_path, monkeypatch):
    _patch_clone_with(monkeypatch, lambda: _fake_repo(tmp_path, {"app/agent.py": RCE_AGENT}))
    rec = rs.scan_remote_repo("https://github.com/o/rce")
    assert rec["findings"], "expected the confused-deputy finding to surface"
    for f in rec["findings"]:
        assert f["file"] == "o/rce/app/agent.py"
        assert rs._TMP_PREFIX not in f["file"]
        assert tempfile.gettempdir() not in (f.get("location") or "")


def test_unparseable_or_import_crashing_code_is_never_run(tmp_path, monkeypatch):
    # If we were importing the target, SystemExit here would abort the scan.
    _patch_clone_with(monkeypatch, lambda: _fake_repo(tmp_path, {
        "bad.py": IMPORT_CRASHES,
        "ok.py": RCE_AGENT,
    }))
    rec = rs.scan_remote_repo("https://github.com/o/mix")
    # ok.py still produced its finding; bad.py was parsed (not executed) fine
    assert any(f["detector"] == "confused-deputy" for f in rec["findings"])


def test_no_strands_code_is_a_distinct_error(tmp_path, monkeypatch):
    _patch_clone_with(monkeypatch, lambda: _fake_repo(tmp_path, {
        "README.md": "# hello",
        "util.py": "def add(a, b):\n    return a + b\n",
    }))
    with pytest.raises(rs.NoStrandsCode):
        rs.scan_remote_repo("https://github.com/o/empty")


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privilege on Windows")
def test_symlink_escaping_the_clone_is_not_scanned(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret_agent.py").write_text(RCE_AGENT, encoding="utf-8")

    def build():
        dest = tmp_path / "repo"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "real.py").write_text(CLEAN_AGENT, encoding="utf-8")
        os.symlink(outside / "secret_agent.py", dest / "linked.py")
        os.symlink(outside, dest / "linkeddir")
        return str(dest)

    _patch_clone_with(monkeypatch, build)
    rec = rs.scan_remote_repo("https://github.com/o/link")
    for f in rec["findings"]:
        assert "linked" not in f["file"], f"scanned a symlink escaping the clone: {f['file']}"


def test_oversized_tree_is_rejected(tmp_path, monkeypatch):
    _patch_clone_with(monkeypatch, lambda: _fake_repo(tmp_path, {"agent.py": CLEAN_AGENT}))
    monkeypatch.setattr(rs, "MAX_TREE_BYTES", 10)  # everything is "too big"
    with pytest.raises(rs.RepoTooLarge):
        rs.scan_remote_repo("https://github.com/o/big")


def test_precheck_rejects_repo_over_size_cap(monkeypatch):
    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, *_a): return b'{"size": 999999999, "private": false}'

    monkeypatch.setattr(rs.urllib.request, "urlopen", lambda *a, **k: FakeResp())
    with pytest.raises(rs.RepoTooLarge):
        rs._precheck_repo_size(rs.parse_github_target("https://github.com/o/r"))


# --------------------------------------------------------------------------- #
# End-to-end (opt-in): a real shallow clone at a pinned commit must reproduce
# the hand-verified findings from references/real_world_findings.md.
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    os.environ.get("RUN_REMOTE_INTEGRATION") != "1",
    reason="network test; set RUN_REMOTE_INTEGRATION=1 to run",
)
def test_live_clone_reproduces_kyopark_findings():
    url = ("https://github.com/kyopark2014/strands-agent/commit/"
           "74af997c3c626fb6ff69359e239c8dde34301c97")
    rec = rs.scan_remote_repo(url)
    hits = {
        (f["detector"], f["file"], f["line"])
        for f in rec["findings"]
    }
    expected = {
        ("confused-deputy", "kyopark2014/strands-agent/application/strands_agent.py", 195),
        ("confused-deputy", "kyopark2014/strands-agent/application/strands_agent.py", 545),
        ("exfiltration-capability-pair",
         "kyopark2014/strands-agent/application/strands_agent.py", 278),
    }
    assert expected <= hits, f"missing hand-verified findings; got {sorted(hits)}"
