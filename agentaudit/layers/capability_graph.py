"""Tool-capability trust graph — dangerous capability-pair detection.

The per-tool detectors in :mod:`static_graph` catch flaws *inside* one tool.
This module works at the level of the agent's whole tool set: it classifies what
each ``@tool`` can actually *do* (write, reach the network, read secrets, read
shared data) and flags combinations that together make data exfiltration
possible — even when no single tool is dangerous on its own.

That "capability pair" is the finding Cedar policies are generated from
(see :mod:`agentaudit.remediation.cedar`): a policy denying the specific
tool-call sequence is a precise, enforceable remediation.
"""

from __future__ import annotations

import ast
import re
from itertools import product
from pathlib import Path

from agentaudit.layers.static_graph import (
    _all_calls,
    _call_func_leaf,
    _dotted_name,
    discover_tools,
)
from agentaudit.models import Confidence, Finding, Layer, Remediation, Severity

# --- capability vocabularies ------------------------------------------------

# NETWORK: the tool can send data off-host.
_NET_DOTTED = re.compile(r"^(requests|httpx|aiohttp|urllib|socket|smtplib)\b", re.IGNORECASE)
_NET_LEAF = {"urlopen", "post", "put", "patch", "request", "send", "sendmail", "publish"}
_NET_BASES = {"requests", "httpx", "session", "client", "http", "aiohttp", "socket", "smtplib"}
_NET_NAME = re.compile(r"(send_email|send_message|webhook|upload|post_to|notify|publish|export)",
                       re.IGNORECASE)

# WRITE: the tool can persist or mutate state.
_WRITE_DOTTED = re.compile(r"^(os\.(remove|unlink|rmdir|rename)|shutil\.(rmtree|move|copy))$",
                           re.IGNORECASE)
_WRITE_LEAF = {"write", "writelines", "put_object", "insert", "update_item", "put_item",
               "save", "dump", "commit", "delete_object", "create", "update", "delete"}
_WRITE_NAME = re.compile(r"(write|save|store|persist|update|delete|remove|create|upload)",
                         re.IGNORECASE)

# READ_SECRET: the tool can obtain credentials / secret material.
_SECRET_LEAF = {"get_secret_value", "get_parameter", "get_parameters", "get_random_password"}
_SECRET_ENV = re.compile(r"(secret|token|password|passwd|api_key|apikey|credential|private_key)",
                         re.IGNORECASE)
_SECRET_NAME = re.compile(r"(secret|credential|token|password|api_key|apikey)", re.IGNORECASE)

# READ_DATA: the tool reads shared/persistent data.
_READ_LEAF = {"get", "get_item", "query", "scan", "fetch", "find", "select", "read",
              "get_object", "list_objects_v2", "download_file"}


def _uses_env_secret(fn: ast.FunctionDef) -> bool:
    """os.environ[...] / os.getenv(...) with a secret-looking key."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Subscript):
            base = _dotted_name(node.value)
            if base.endswith("environ"):
                for c in ast.walk(node.slice):
                    if isinstance(c, ast.Constant) and isinstance(c.value, str):
                        if _SECRET_ENV.search(c.value):
                            return True
        if isinstance(node, ast.Call) and _call_func_leaf(node) in {"getenv", "environ"}:
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    if _SECRET_ENV.search(a.value):
                        return True
    return False


def classify_tool(tool) -> set[str]:
    """Return the set of capabilities a tool exercises."""
    caps: set[str] = set()
    name = tool.name.lower()
    doc = (tool.docstring or "").lower()

    if _NET_NAME.search(name):
        caps.add("NETWORK")
    if _WRITE_NAME.search(name):
        caps.add("WRITE")
    if _SECRET_NAME.search(name):
        caps.add("READ_SECRET")

    if _uses_env_secret(tool.fn):
        caps.add("READ_SECRET")

    for call in _all_calls(tool.fn):
        dotted = _dotted_name(call.func)
        leaf = _call_func_leaf(call)
        base = dotted.split(".")[0] if dotted else ""

        if _NET_DOTTED.match(dotted) or (leaf in _NET_LEAF and base in _NET_BASES) or leaf == "urlopen":
            caps.add("NETWORK")
        if _WRITE_DOTTED.match(dotted) or leaf in _WRITE_LEAF:
            caps.add("WRITE")
        if leaf in _SECRET_LEAF:
            caps.add("READ_SECRET")
        if leaf in _READ_LEAF:
            caps.add("READ_DATA")
        # open(path, "w"/"a") is a write
        if leaf == "open":
            for a in call.args[1:]:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and \
                        any(m in a.value for m in ("w", "a", "+")):
                    caps.add("WRITE")

    if "network" in doc or "http" in doc:
        caps.add("NETWORK")
    return caps


# Capability pairs that together enable exfiltration.
DANGEROUS_PAIRS = {
    ("WRITE", "NETWORK"): (
        Severity.HIGH,
        "write-plus-network",
        "A tool that can modify state combined with a tool that can reach the "
        "network lets an attacker stage data and then exfiltrate it.",
    ),
    ("READ_SECRET", "NETWORK"): (
        Severity.CRITICAL,
        "secret-plus-network",
        "A tool that can read credentials combined with a tool that can reach "
        "the network allows direct credential exfiltration.",
    ),
    ("READ_DATA", "NETWORK"): (
        Severity.MEDIUM,
        "read-plus-network",
        "A tool that reads shared data combined with network egress enables "
        "bulk data exfiltration.",
    ),
}


def analyze_capability_pairs(agent_path: str | Path) -> list[Finding]:
    """Flag dangerous capability pairs across the agent's tool set."""
    path = Path(agent_path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    file = str(path).replace("\\", "/")

    tools = discover_tools(tree)
    caps = {t.name: classify_tool(t) for t in tools}

    findings: list[Finding] = []
    seen: set[tuple] = set()

    for (cap_a, cap_b), (sev, slug, why) in DANGEROUS_PAIRS.items():
        holders_a = [n for n, c in caps.items() if cap_a in c]
        holders_b = [n for n, c in caps.items() if cap_b in c]
        for ta, tb in product(holders_a, holders_b):
            key = (slug, tuple(sorted({ta, tb})))
            if key in seen:
                continue
            seen.add(key)
            same = ta == tb
            line = next((t.line for t in tools if t.name == ta), 0)
            scope = (f"single tool '{ta}' holds both capabilities"
                     if same else f"'{ta}' ({cap_a}) + '{tb}' ({cap_b})")
            findings.append(
                Finding(
                    detector="exfiltration-capability-pair",
                    layer=Layer.ARCHITECTURAL,
                    severity=sev,
                    title=f"Exfiltration path: {cap_a} + {cap_b} via {scope}",
                    description=(
                        f"{why} Detected: {scope}. An attacker who can steer the agent "
                        f"can chain these tool calls in a single session to move data "
                        f"out of the trust boundary."
                    ),
                    file=file,
                    line=line,
                    evidence=f"{ta} caps={sorted(caps[ta])}; {tb} caps={sorted(caps[tb])}",
                    confidence=Confidence.HEURISTIC,
                    remediation=Remediation(
                        summary=("Break the chain with an AgentCore Cedar policy that "
                                 "forbids the egress leg, or split the capabilities "
                                 "across isolated agents/gateways."),
                        before=f"# {ta} and {tb} are both reachable in one session",
                        after=(
                            "forbid(\n"
                            "  principal is AgentCore::IamEntity,\n"
                            f'  action == AgentCore::Action::"<target>___{tb}",\n'
                            '  resource == AgentCore::Gateway::"<gateway-arn>"\n'
                            ");"
                        ),
                    ),
                    fingerprint=f"exfiltration-capability-pair:{slug}:{file}:{ta}:{tb}",
                    metadata={
                        "pattern": slug,
                        "capability_a": cap_a,
                        "capability_b": cap_b,
                        "tool_a": ta,
                        "tool_b": tb,
                        "same_tool": same,
                    },
                )
            )
    return findings
