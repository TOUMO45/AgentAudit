"""Layer 2 — Static Tool Trust Graph Analyzer  (THE DECISIVE GATE).

This is the innovation the whole product rests on (charter "decisive gate"). It
parses a Strands agent's source with the stdlib :mod:`ast` — no third-party SAST
framework (charter stack rule) — discovers ``@tool`` definitions, builds a trust
graph, and flags three pattern classes drawn from real web-application
penetration testing, mapped onto the agent world:

* ``idor-in-agent``  — a subject/resource id comes from the conversation and is
  used to read a shared data store with no ownership check.
* ``confused-deputy`` — an untrusted parameter is forwarded, unvalidated, into a
  privileged sink.
* ``excessive-agency`` — a tool whose declared purpose is read-only performs a
  destructive / out-of-scope operation.

Design principle: every rule is deterministic and explainable (a security tool
must justify each finding), and every rule is tuned so the hardened negative
controls produce **zero** findings. When in doubt the analyzer stays silent —
false positives are worse than a missed edge case for adoption.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from pathlib import Path

from agentaudit.models import (
    Confidence,
    Finding,
    Layer,
    Remediation,
    Severity,
)

# --- detection vocabularies (documented in references/trap-design.md) ------

# Parameters that name a subject/principal or a cross-tenant resource. When one
# of these arrives as a free tool parameter (model-controllable) it is the
# classic IDOR lever.
_ID_PARAM = re.compile(
    r"^(user|account|customer|owner|client|tenant|org|member|subject|principal"
    r"|resource|record|document|doc|file|order|invoice|ticket|case)_?id$",
    re.IGNORECASE,
)

# Calls that constitute an authorization / ownership check. Their presence in a
# tool body clears an IDOR flag.
_AUTHZ_CALLS = {
    "assert_owner", "check_owner", "verify_owner", "require_owner", "is_owner",
    "ensure_owner", "authorize", "check_access", "verify_access", "require_access",
    "check_permission", "has_permission", "enforce_scope", "require_scope",
}

# Calls that validate / sanitize an untrusted value. Their result is trusted.
_VALIDATION_CALLS = {
    "validate", "sanitize", "is_allowed", "check_allowed", "allowlist",
    "whitelist", "is_whitelisted", "clean", "escape", "coerce", "assert_valid",
} | {c for c in _AUTHZ_CALLS}

# Privileged sinks: dotted stdlib danger + name fragments implying elevation.
_SINK_DOTTED = {"os.system", "subprocess.run", "subprocess.call", "subprocess.popen"}
_SINK_BARE = {"exec", "eval"}
_SINK_FRAGMENTS = re.compile(
    r"(admin|escalate|sudo|grant|revoke|delete|drop|destroy|credit_ledger"
    r"|transfer|wire|payout|run_shell|execute|modify_role|set_role)",
    re.IGNORECASE,
)

# Read-only declared intent (tool name prefixes).
_READ_PREFIXES = (
    "get", "read", "list", "search", "lookup", "fetch", "view", "find",
    "show", "describe", "query", "check", "whoami", "count",
)

# Destructive operations that betray excessive agency inside a read tool.
_DANGEROUS_DOTTED = re.compile(
    r"^(os\.(system|remove|unlink|rmdir)"
    r"|subprocess\.(run|call|popen|check_output)"
    r"|shutil\.(rmtree|move|copy)"
    r")$",
    re.IGNORECASE,
)
_DANGEROUS_METHODS = {
    "delete", "remove", "write", "writelines", "update", "create", "insert",
    "put", "post", "send", "drop", "truncate", "execute",
}
_DANGEROUS_BARE = {"exec", "eval"}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------
def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted name for a Name/Attribute call target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _call_func_leaf(call: ast.Call) -> str:
    """The final identifier of a call target (``a.b.c`` -> ``c``)."""
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _is_tool_decorator(dec: ast.expr) -> bool:
    """True for ``@tool`` and ``@tool(...)`` (from ``strands import tool``)."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    return _call_func_leaf_from_expr(target) == "tool"


def _call_func_leaf_from_expr(expr: ast.expr) -> str:
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Name):
        return expr.id
    return ""


def _has_context_flag(dec: ast.expr) -> bool:
    """``@tool(context=True)`` marks the first arg as an injected ToolContext."""
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg == "context" and isinstance(kw.value, ast.Constant) and kw.value.value:
                return True
    return False


def _param_names(fn: ast.FunctionDef) -> list[str]:
    a = fn.args
    names = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names


def _is_context_param(fn: ast.FunctionDef, name: str, context_flag: bool) -> bool:
    if name in {"self", "cls"}:
        return True
    if name in {"ctx", "context", "session", "agent", "tool_context"}:
        return True
    # annotation ToolContext
    for p in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs):
        if p.arg == name and p.annotation is not None:
            if _dotted_name(p.annotation).split(".")[-1] == "ToolContext":
                return True
    # first positional arg when context=True
    if context_flag:
        positional = [*fn.args.posonlyargs, *fn.args.args]
        if positional and positional[0].arg == name:
            return True
    return False


def _local_literal_names(fn: ast.FunctionDef) -> set[str]:
    """Names bound to an in-function literal / comprehension — NOT shared
    stores, so an access on them is not a cross-tenant read."""
    out: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(
            node.value, (ast.Dict, ast.List, ast.Set, ast.Constant,
                         ast.ListComp, ast.DictComp, ast.SetComp)
        ):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out.add(tgt.id)
    return out


def _all_calls(fn: ast.FunctionDef) -> list[ast.Call]:
    return [n for n in ast.walk(fn) if isinstance(n, ast.Call)]


def _validated_aliases(fn: ast.FunctionDef) -> set[str]:
    """Locals assigned from a validation call — their value is trusted."""
    out: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if _call_func_leaf(node.value) in _VALIDATION_CALLS:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        out.add(tgt.id)
    return out


def _context_derived_aliases(fn: ast.FunctionDef, ctx_params: set[str]) -> set[str]:
    """Locals whose value is derived from a context parameter (trusted identity)."""
    out: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            used = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
            if used & ctx_params:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        out.add(tgt.id)
    return out


# ---------------------------------------------------------------------------
# Tool model
# ---------------------------------------------------------------------------
class ToolDef:
    def __init__(self, fn: ast.FunctionDef, context_flag: bool):
        self.fn = fn
        self.name = fn.name
        self.line = fn.lineno
        self.context_flag = context_flag
        self.ctx_params = {
            n for n in _param_names(fn) if _is_context_param(fn, n, context_flag)
        }
        self.untrusted_params = [
            n for n in _param_names(fn) if n not in self.ctx_params
        ]
        self.docstring = ast.get_docstring(fn) or ""


def discover_tools(tree: ast.Module) -> list[ToolDef]:
    tools: list[ToolDef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if _is_tool_decorator(dec):
                    tools.append(ToolDef(node, _has_context_flag(dec)))
                    break
    return tools


def extract_system_prompt(tree: ast.Module) -> str | None:
    """Pull the system prompt from ``SYSTEM_PROMPT = ...`` or the
    ``Agent(system_prompt=...)`` kwarg. Only resolves static string literals."""

    def const_str(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = const_str(node.left), const_str(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    # Agent(system_prompt=...)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_func_leaf(node) == "Agent":
            for kw in node.keywords:
                if kw.arg == "system_prompt":
                    if isinstance(kw.value, ast.Name):
                        break  # resolve via module var below
                    s = const_str(kw.value)
                    if s is not None:
                        return s
    # SYSTEM_PROMPT = "..."
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id.upper() == "SYSTEM_PROMPT":
                    s = const_str(node.value)
                    if s is not None:
                        return s
    return None


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
def _detect_idor(tool: ToolDef, file: str) -> Finding | None:
    id_params = [p for p in tool.untrusted_params if _ID_PARAM.match(p)]
    if not id_params:
        return None

    local_literals = _local_literal_names(tool.fn)
    calls = _all_calls(tool.fn)
    has_authz = any(_call_func_leaf(c) in _AUTHZ_CALLS for c in calls)
    if has_authz:
        return None  # ownership enforced -> safe

    # Does an id param index / query a *shared* (non-local) store?
    def touches_store(pname: str) -> str | None:
        for node in ast.walk(tool.fn):
            # SUBSCRIPT:  STORE[pname]
            if isinstance(node, ast.Subscript):
                base = node.value
                idx_names = {n.id for n in ast.walk(node.slice) if isinstance(n, ast.Name)}
                if pname in idx_names and isinstance(base, ast.Name) and base.id not in local_literals:
                    return f"{base.id}[{pname}]"
            # LOOKUP CALL:  store.get(pname) / db.query(pname) / fetch(pname)
            if isinstance(node, ast.Call):
                leaf = _call_func_leaf(node)
                if leaf in {"get", "query", "fetch", "find", "find_one", "select", "load", "read"}:
                    arg_names = {n.id for a in node.args for n in ast.walk(a) if isinstance(n, ast.Name)}
                    if pname in arg_names:
                        base = node.func.value if isinstance(node.func, ast.Attribute) else None
                        if not (isinstance(base, ast.Name) and base.id in local_literals):
                            return f"{leaf}({pname})"
        return None

    for p in id_params:
        access = touches_store(p)
        if access:
            return Finding(
                detector="idor-in-agent",
                layer=Layer.ARCHITECTURAL,
                severity=Severity.CRITICAL,
                title=f"IDOR-in-Agent: tool '{tool.name}' trusts a caller-supplied id",
                description=(
                    f"Tool '{tool.name}' accepts '{p}' from the conversation and uses it "
                    f"to access a shared data store ({access}) with no ownership check "
                    f"against an authenticated principal. A user can steer the agent to "
                    f"read or act on another principal's record (Insecure Direct Object "
                    f"Reference)."
                ),
                file=file,
                line=tool.line,
                evidence=f"parameter '{p}' -> {access}; no authorization call in tool body",
                confidence=Confidence.DETERMINISTIC,
                remediation=Remediation(
                    summary=(
                        "Derive the principal from the authenticated session "
                        "(ToolContext), not from a tool argument, and enforce ownership."
                    ),
                    before=f"def {tool.name}({p}: str):\n    record = STORE[{p}]",
                    after=(
                        f"@tool(context=True)\n"
                        f"def {tool.name}(ctx: ToolContext):\n"
                        f"    {p} = ctx.session.state['{p}']\n"
                        f"    assert_owner(ctx.actor_id, {p})\n"
                        f"    record = STORE[{p}]"
                    ),
                ),
                metadata={"pattern": "idor", "param": p, "tool": tool.name},
            )
    return None


def _nonpayload_params(fn: ast.FunctionDef) -> set[str]:
    """Params that cannot carry an injection payload: bool/int-typed or
    bool/int-defaulted (flags like ``ignore_errors``, ``verbose``, ``timeout``).
    Excluding these removes a whole class of confused-deputy false positives
    (verified against strands_tools/shell.py: the ``ignore_errors`` flag)."""
    out: set[str] = set()
    a = fn.args
    params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    for p in params:
        ann = _dotted_name(p.annotation).split(".")[-1] if p.annotation is not None else ""
        if ann in {"bool", "int", "float"}:
            out.add(p.arg)
    # bool/int defaults
    defaulted = list(zip([*a.posonlyargs, *a.args][-len(a.defaults):] if a.defaults else [], a.defaults))
    defaulted += list(zip(a.kwonlyargs, a.kw_defaults or []))
    for param, default in defaulted:
        if isinstance(default, ast.Constant) and isinstance(default.value, (bool, int, float)):
            out.add(param.arg)
    return out


def _detect_confused_deputy(tool: ToolDef, file: str) -> Finding | None:
    validated = _validated_aliases(tool.fn)
    ctx_derived = _context_derived_aliases(tool.fn, tool.ctx_params)
    untrusted = set(tool.untrusted_params) - _nonpayload_params(tool.fn)

    # Propagate untrusted-ness through plain `x = param` aliases.
    for node in ast.walk(tool.fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            if node.value.id in untrusted and node.value.id not in validated:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        untrusted.add(tgt.id)

    tainted = (untrusted - validated) - ctx_derived
    if not tainted:
        return None

    for call in _all_calls(tool.fn):
        dotted = _dotted_name(call.func).lower()
        leaf = _call_func_leaf(call)
        is_sink = (
            dotted in _SINK_DOTTED
            or leaf in _SINK_BARE
            or bool(_SINK_FRAGMENTS.search(leaf))
        )
        if not is_sink:
            continue
        # direct Name arguments (not values embedded in f-strings)
        arg_names = {
            a.id for a in call.args if isinstance(a, ast.Name)
        } | {
            kw.value.id for kw in call.keywords if isinstance(kw.value, ast.Name)
        }
        hit = arg_names & tainted
        if hit:
            param = sorted(hit)[0]
            return Finding(
                detector="confused-deputy",
                layer=Layer.ARCHITECTURAL,
                severity=Severity.CRITICAL,
                title=f"Confused Deputy: tool '{tool.name}' forwards untrusted input to a privileged sink",
                description=(
                    f"Tool '{tool.name}' passes the untrusted value '{param}' directly into "
                    f"the privileged operation '{leaf}(...)' without validation. The tool "
                    f"becomes a deputy the caller can confuse into performing a privileged "
                    f"action on their behalf."
                ),
                file=file,
                line=tool.line,
                evidence=f"'{param}' -> {leaf}(...) with no validation/allowlist between",
                confidence=Confidence.DETERMINISTIC,
                remediation=Remediation(
                    summary="Validate the input against a strict allowlist before the privileged call.",
                    before=f"    {leaf}({param})",
                    after=f"    safe = validate_{param}({param})   # raises on anything off the allowlist\n    {leaf}(safe)",
                ),
                metadata={"pattern": "confused-deputy", "param": param, "sink": leaf, "tool": tool.name},
            )
    return None


_SSRF_PARAM = re.compile(r"(url|uri|endpoint|webhook|callback|href|link)", re.IGNORECASE)
_HTTP_SINK_DOTTED = re.compile(
    r"^(requests|httpx|aiohttp)\.|^urllib\.request\.urlopen$|^urllib\.request\b", re.IGNORECASE
)
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen", "fetch"}
_HTTP_BASES = {"requests", "httpx", "session", "client", "http", "aiohttp"}
_ALLOWLIST_HINT = re.compile(r"(allow|whitelist|permit|urlparse|urlsplit)", re.IGNORECASE)


def _detect_ssrf(tool: ToolDef, file: str) -> Finding | None:
    ssrf_params = [p for p in tool.untrusted_params if _SSRF_PARAM.search(p)]
    if not ssrf_params:
        return None

    # An allowlist / URL-parsing guard anywhere in the body clears the flag.
    for node in ast.walk(tool.fn):
        if isinstance(node, ast.Name) and _ALLOWLIST_HINT.search(node.id):
            return None
        if isinstance(node, ast.Call) and _call_func_leaf(node) in _VALIDATION_CALLS:
            return None

    for call in _all_calls(tool.fn):
        dotted = _dotted_name(call.func)
        leaf = _call_func_leaf(call)
        base = dotted.split(".")[0] if dotted else ""
        is_http = bool(_HTTP_SINK_DOTTED.match(dotted)) or (
            leaf in _HTTP_METHODS and base in _HTTP_BASES
        ) or leaf == "urlopen"
        if not is_http:
            continue
        used = {n.id for a in call.args for n in ast.walk(a) if isinstance(n, ast.Name)}
        used |= {n.id for kw in call.keywords for n in ast.walk(kw.value) if isinstance(n, ast.Name)}
        hit = set(ssrf_params) & used
        if hit:
            param = sorted(hit)[0]
            return Finding(
                detector="ssrf-via-tool-param",
                layer=Layer.ARCHITECTURAL,
                severity=Severity.HIGH,
                title=f"SSRF: tool '{tool.name}' fetches a caller-controlled URL",
                description=(
                    f"Tool '{tool.name}' passes the caller-controlled parameter '{param}' "
                    f"straight into an HTTP request ('{dotted or leaf}(...)') with no domain "
                    f"allowlist. A user can point it at internal services "
                    f"(169.254.169.254, localhost, RFC-1918) — server-side request forgery."
                ),
                file=file,
                line=tool.line,
                evidence=f"'{param}' -> {dotted or leaf}(...); no allowlist/urlparse guard in body",
                confidence=Confidence.DETERMINISTIC,
                remediation=Remediation(
                    summary="Validate the host against an explicit allowlist before the request.",
                    before=f"    requests.get({param})",
                    after=(
                        f"    host = urlparse({param}).netloc\n"
                        f"    if host not in ALLOWED_HOSTS:\n"
                        f"        raise ValueError('host not allowed')\n"
                        f"    requests.get({param})"
                    ),
                ),
                metadata={"pattern": "ssrf", "param": param, "sink": dotted or leaf, "tool": tool.name},
            )
    return None


def _detect_excessive_agency(tool: ToolDef, file: str) -> Finding | None:
    name = tool.name.lower()
    read_intent = name.startswith(_READ_PREFIXES) or "read-only" in tool.docstring.lower()
    if not read_intent:
        return None

    for node in ast.walk(tool.fn):
        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            leaf = _call_func_leaf(node)
            dangerous = (
                bool(_DANGEROUS_DOTTED.match(dotted))
                or leaf in _DANGEROUS_BARE
                or (isinstance(node.func, ast.Attribute) and leaf in _DANGEROUS_METHODS)
            )
            if dangerous:
                return Finding(
                    detector="excessive-agency",
                    layer=Layer.ARCHITECTURAL,
                    severity=Severity.HIGH,
                    title=f"Excessive Agency: read-named tool '{tool.name}' performs a destructive operation",
                    description=(
                        f"Tool '{tool.name}' presents a read-only purpose but its "
                        f"implementation calls '{dotted or leaf}(...)', a destructive / "
                        f"out-of-scope capability. Its real authority is far wider than "
                        f"its declared purpose (least-authority violation)."
                    ),
                    file=file,
                    line=tool.line,
                    evidence=f"read-intent name '{tool.name}' but calls '{dotted or leaf}(...)'",
                    confidence=Confidence.HEURISTIC,
                    remediation=Remediation(
                        summary="Split read and write capabilities; keep read tools side-effect free.",
                        before=f"@tool\ndef {tool.name}(...):  # 'read-only'\n    {dotted or leaf}(...)",
                        after=f"@tool\ndef {tool.name}(...):  # read-only, no side effects\n    return LOOKUP.get(key)",
                    ),
                    metadata={"pattern": "excessive-agency", "sink": dotted or leaf, "tool": tool.name},
                )
    return None


# ---------------------------------------------------------------------------
# Secrets-in-system-prompt (Phase 2 item 2.2)
# ---------------------------------------------------------------------------
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GENERIC_TOKEN = re.compile(r"[A-Za-z0-9/+=_\-]{32,}")
_SECRET_KEYWORD = re.compile(r"(key|token|secret|password|passwd|apikey|api_key|credential)", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_prompt_secrets(prompt: str, file: str) -> list[Finding]:
    """Flag hard-coded credentials embedded in the system prompt.

    Two signals: a precise AWS-key regex, and a generic high-entropy token that
    sits near a secret-ish keyword (entropy screens out ordinary long words).
    Deduplicated by the matched value so one secret yields one finding.
    """
    if not prompt:
        return []
    found: dict[str, str] = {}  # secret value -> kind

    for m in _AWS_ACCESS_KEY.finditer(prompt):
        found[m.group(0)] = "AWS access key id"

    for m in _GENERIC_TOKEN.finditer(prompt):
        tok = m.group(0)
        if tok in found:
            continue
        window = prompt[max(0, m.start() - 40): m.end() + 40]
        if _SECRET_KEYWORD.search(window) and _shannon_entropy(tok) >= 3.5:
            found[tok] = "high-entropy secret"

    findings: list[Finding] = []
    for value, kind in found.items():
        masked = value[:4] + "…" + value[-2:] if len(value) > 8 else "…"
        findings.append(
            Finding(
                detector="secret-in-prompt",
                layer=Layer.ARCHITECTURAL,
                severity=Severity.CRITICAL,
                title=f"Hard-coded {kind} in the system prompt",
                description=(
                    f"The system prompt embeds what looks like a {kind} ('{masked}'). "
                    f"Anything in the prompt is visible to the model and can be leaked "
                    f"through prompt-extraction attacks; secrets must never live in it."
                ),
                file=file,
                evidence=f"{kind}: {masked} (entropy {_shannon_entropy(value):.2f})",
                confidence=Confidence.DETERMINISTIC,
                remediation=Remediation(
                    summary="Load the secret from the environment / a secrets manager, never the prompt.",
                    before='SYSTEM_PROMPT = "... use key AKIA...EXAMPLE ..."',
                    after='key = os.environ["AWS_ACCESS_KEY_ID"]  # never in the prompt',
                ),
                fingerprint=f"secret-in-prompt:{file}:{masked}",
                metadata={"kind": kind},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def analyze(agent_path: str | Path) -> list[Finding]:
    """Run all static detectors against a Strands agent source file."""
    path = Path(agent_path)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    file = str(path).replace("\\", "/")

    findings: list[Finding] = []
    for tool in discover_tools(tree):
        for detector in (_detect_idor, _detect_confused_deputy, _detect_excessive_agency, _detect_ssrf):
            f = detector(tool, file)
            if f is not None:
                findings.append(f)

    findings.extend(detect_prompt_secrets(extract_system_prompt(tree) or "", file))
    return findings
