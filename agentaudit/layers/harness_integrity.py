"""Harness-integrity layer — CoreBreak model-skip check (CVE-2026-18830).

Background (see ``references/corebreak_detector_basis.md`` for the real source
excerpt and CVE references)
--------------------------------------------------------------------------------
The Strands event loop skips the model call entirely when the *latest* message
already contains a ``toolUse`` content block::

    # strands/event_loop/event_loop.py  (v1.55.0, lines 293-297)
    # Skip model invocation if the latest message contains ToolUse
    elif _has_tool_use_in_latest_message(agent.messages):
        stop_reason = "tool_use"
        message = agent.messages[-1]

``_has_tool_use_in_latest_message`` (line 105) just checks ``messages[-1]`` for a
``"toolUse"`` key. Disclosed as **CoreBreak / CVE-2026-18830** (CVSS 4.0 **8.6**,
CWE-1287) at Black Hat 2026. AWS added server-side input validation to the
*managed* AgentCore ``InvokeHarness`` API but **declined a code change to the
open-source Strands Python SDK** — every released version, up to and including
the pinned ``strands-agents==1.55.0``, still contains the path.

What this detector does — and does not — claim
--------------------------------------------------------------------------------
It does **not** exploit anything and it does **not** patch the SDK. It is a
static (``ast``-only) check of the *user's own agent code* for the one thing the
user can control: whether caller-supplied conversation history reaches the Agent
**without** first having attacker-suppliable ``toolUse`` / ``tool_use`` content
blocks stripped out.

* **FAIL (CRITICAL):** the module forwards caller-controlled ``messages`` /
  conversation history into ``Agent(...)`` / ``agent.messages`` and there is no
  sanitization step and no managed-InvokeHarness marker. An attacker who
  controls the last message can run a configured tool with chosen arguments,
  skipping the model and every model-time guardrail.
* **CLEAN (no finding):** the agent strips ``toolUse``/``tool_use`` blocks from
  inbound history before the harness, registers a ``BeforeModelCall`` guard, or
  the ``<agent>.deploy.json`` descriptor explicitly attests managed-InvokeHarness
  deployment (``{"corebreak_mitigation": true}`` or
  ``{"invocation": "agentcore-managed-invoke-harness"}``). Whether an agent is
  invoked only through the patched managed API is a *deployment* fact that
  cannot be read from local source, so it is honoured **only** when the deployer
  declares it in that descriptor. User-facing "pass" wording (never "detects
  CoreBreak"):

      "strands-agents is affected by CVE-2026-18830 (CoreBreak) and has no
      upstream fix; verified your agent strips caller-suppliable tool_use blocks
      from incoming message history before the harness — or its deploy descriptor
      attests it runs only via the patched managed InvokeHarness API."

A single-prompt agent that never ingests structured caller history is not
flagged — CoreBreak needs the attacker to place a ``toolUse`` block into
``messages[-1]``, which requires the app to accept structured message input.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agentaudit.layers.cloud_posture import _discover_config
from agentaudit.models import Confidence, Finding, Layer, Remediation, Severity

CVE = "CVE-2026-18830"
ALIAS = "CoreBreak"
AFFECTED = "strands-agents<=1.55.0 (all released versions; no upstream fix)"

# Parameters / keys that typically carry caller-controlled conversation history.
_HISTORY_NAMES = {
    "messages", "history", "conversation", "conversation_history", "chat_history",
    "message_history", "msgs", "event", "payload", "request", "body", "request_body",
}
_HISTORY_KEYS = {"messages", "history", "conversation", "chat_history",
                 "conversation_history", "message_history"}

# A sanitization step that removes tool_use blocks from message history.
_SANITIZE_RE = re.compile(
    r"(strip|saniti[sz]e|scrub|filter|clean|drop|remove|reject|deny|purge)[_a-z]*"
    r"[_a-z]*(tool_?use|message|history|block|content)"
    r"|(tool_?use|message|history)[_a-z]*(strip|saniti[sz]e|scrub|filter|clean|drop|remove|reject)",
    re.IGNORECASE,
)
# A pre-model interception point the developer can use to enforce the same thing.
_HOOK_RE = re.compile(r"before_?model_?call|BeforeModelCall|BeforeModelInvocation", re.IGNORECASE)
_TOOLUSE_LITERAL = {"toolUse", "tool_use"}


def _leaf(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _history_sources(tree: ast.Module) -> set[str]:
    """Local names that hold caller-supplied conversation history."""
    sources: set[str] = set()

    # 1. function parameters named like history, or a param that is a dict/event
    #    the body immediately indexes with a history key.
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)}
        for p in params:
            if p in _HISTORY_NAMES and p in {"messages", "history", "conversation",
                                             "conversation_history", "chat_history",
                                             "message_history", "msgs"}:
                sources.add(p)
        # x = event["messages"] / event.get("messages") / event.messages
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Subscript, ast.Call, ast.Attribute)):
                v = node.value
                base = key = None
                if isinstance(v, ast.Subscript) and isinstance(v.value, ast.Name):
                    base = v.value.id
                    if isinstance(v.slice, ast.Constant):
                        key = v.slice.value
                elif isinstance(v, ast.Call) and _leaf(v) == "get" and v.args:
                    if isinstance(v.func, ast.Attribute) and isinstance(v.func.value, ast.Name):
                        base = v.func.value.id
                    if isinstance(v.args[0], ast.Constant):
                        key = v.args[0].value
                elif isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name):
                    base = v.value.id
                    key = v.attr
                if base in params and isinstance(key, str) and key in _HISTORY_KEYS:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            sources.add(tgt.id)

    # 2. propagate through plain aliases: y = x
    for _ in range(3):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and node.value.id in sources:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        sources.add(tgt.id)
    return sources


def _reaches_agent(tree: ast.Module, sources: set[str]) -> tuple[bool, str, int]:
    """True if a history source flows into Agent(messages=...) or agent.messages."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = _leaf(node)
            # Agent(messages=<source>) / SomethingAgent(messages=<source>)
            if fname == "Agent" or fname.endswith("Agent"):
                for kw in node.keywords:
                    if kw.arg == "messages" and _names_in(kw.value) & sources:
                        return True, "Agent(messages=…)", getattr(node, "lineno", 0)
            # agent.messages.extend(<source>) / .append(<source>) / agent.invoke(<source>)
            if isinstance(node.func, ast.Attribute) and fname in {
                "extend", "append", "invoke", "invoke_async", "stream_async", "run", "run_async",
            }:
                owner = node.func.value
                owner_is_messages = (
                    isinstance(owner, ast.Attribute) and owner.attr == "messages"
                )
                args_hist = any(_names_in(a) & sources for a in node.args)
                if args_hist and (owner_is_messages or fname in {"invoke", "invoke_async",
                                                                 "stream_async", "run", "run_async"}):
                    return True, f"{fname}(<history>)", getattr(node, "lineno", 0)
        # agent.messages = <source>
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr == "messages":
                    if _names_in(node.value) & sources:
                        return True, "agent.messages = …", getattr(node, "lineno", 0)
    return False, "", 0


def _has_mitigation(tree: ast.Module, source: str, agent_path: str) -> bool:
    # 1. a named sanitize call, or a hook interception point
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _leaf(node)
            if name and _SANITIZE_RE.search(name):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if _SANITIZE_RE.search(node.name) or _HOOK_RE.search(node.name):
                return True
    if _HOOK_RE.search(source):
        return True
    # 2. a comprehension / membership test that filters on a toolUse literal
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            consts = {c.value for c in ast.walk(node) if isinstance(c, ast.Constant)}
            if consts & _TOOLUSE_LITERAL:
                return True
        if isinstance(node, ast.Call) and _leaf(node) in {"get", "pop"}:
            for a in node.args:
                if isinstance(a, ast.Constant) and a.value in _TOOLUSE_LITERAL:
                    return True
    # 3. Explicit deployer attestation in <agent>.deploy.json (the same descriptor
    #    the cloud-posture layer reads). "Invoked only through the patched managed
    #    AgentCore InvokeHarness API" is a *deployment* fact, not a code fact, so
    #    it can only be honoured when the deployer declares it here:
    #        {"corebreak_mitigation": true}
    #      or
    #        {"invocation": "agentcore-managed-invoke-harness"}
    cfg_path = _discover_config(agent_path)
    if cfg_path and Path(cfg_path).exists():
        try:
            import json

            cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cfg = {}
        if cfg.get("corebreak_mitigation") is True:
            return True
        if str(cfg.get("invocation") or "").strip().lower() == "agentcore-managed-invoke-harness":
            return True
    return False


def analyze(agent_path: str) -> list[Finding]:
    """Flag an agent that forwards unsanitized caller history into the Strands
    event loop (CoreBreak / CVE-2026-18830)."""
    source = Path(agent_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(agent_path))
    file = str(agent_path).replace("\\", "/")

    if not ("import strands" in source or "from strands" in source):
        return []

    sources = _history_sources(tree)
    if not sources:
        return []
    reaches, sink, line = _reaches_agent(tree, sources)
    if not reaches:
        return []
    if _has_mitigation(tree, source, agent_path):
        return []

    param = sorted(sources)[0]
    return [
        Finding(
            detector="harness-model-skip-corebreak",
            layer=Layer.ARCHITECTURAL,
            severity=Severity.CRITICAL,
            title=(
                "CoreBreak (CVE-2026-18830): unsanitized caller-supplied message "
                "history reaches the Strands event loop"
            ),
            description=(
                f"This agent forwards caller-controlled conversation history "
                f"('{param}' -> {sink}) into the Strands Agent without a step that "
                f"removes 'toolUse' / 'tool_use' content blocks. On {AFFECTED}, the "
                f"event loop's '_has_tool_use_in_latest_message' check "
                f"(event_loop.py) then skips the model call whenever the latest "
                f"message already contains a toolUse block and dispatches that tool "
                f"directly. An attacker who controls the last message can execute a "
                f"configured tool with attacker-chosen arguments, bypassing the "
                f"model and every guardrail wrapped around the model call. AWS "
                f"patched the managed AgentCore InvokeHarness API for {CVE} but did "
                f"not change the open-source SDK."
            ),
            file=file,
            line=line,
            evidence=(
                f"caller-controlled '{param}' -> {sink}; no toolUse/tool_use "
                f"sanitization, no BeforeModelCall guard, and <agent>.deploy.json "
                f"does not attest managed-InvokeHarness deployment "
                f"(corebreak_mitigation / invocation)"
            ),
            confidence=Confidence.HEURISTIC,
            remediation=Remediation(
                summary=(
                    "Strip caller-suppliable tool_use/toolUse content blocks from "
                    "inbound message history before constructing or invoking the "
                    "Agent. strands-agents has no upstream fix as of 1.55.0, so "
                    "this must be enforced in your code. If the agent is in fact "
                    "invoked only through the patched managed AgentCore "
                    "InvokeHarness API, declare it in <agent>.deploy.json "
                    "(\"corebreak_mitigation\": true)."
                ),
                before=(
                    "messages = event[\"messages\"]\n"
                    "agent = Agent(system_prompt=SP, tools=TOOLS, messages=messages)"
                ),
                after=(
                    "def _strip_tool_use(messages):\n"
                    "    out = []\n"
                    "    for m in messages:\n"
                    "        blocks = [b for b in m.get(\"content\", [])\n"
                    "                  if \"toolUse\" not in b and \"tool_use\" not in b]\n"
                    "        out.append({**m, \"content\": blocks})\n"
                    "    return out\n"
                    "\n"
                    "messages = _strip_tool_use(event[\"messages\"])\n"
                    "agent = Agent(system_prompt=SP, tools=TOOLS, messages=messages)"
                ),
            ),
            fingerprint=f"harness-model-skip-corebreak:{file}:{line}",
            metadata={
                "cve": CVE,
                "alias": ALIAS,
                "cwe": "CWE-1287",
                "affected": AFFECTED,
                "param": param,
                "sink": sink,
            },
        )
    ]
