"""AIBOM (AI Bill of Materials) export — a fourth artifact from ``agentaudit run``.

The output is a **CycloneDX 1.6** BOM (``bomFormat: "CycloneDX"``,
``specVersion: "1.6"``) so it drops into existing SBOM tooling. AgentAudit-specific
facts that CycloneDX has no native field for are carried as ``agentaudit:``-namespaced
``properties`` and, for the exfiltration capability pairs, as ``annotations``.

Everything here is derived from the **same static trust-graph parse** the Layer 2
detectors use (:mod:`agentaudit.layers.static_graph` /
:mod:`agentaudit.layers.capability_graph`) — the agent file is parsed once with
``ast`` and never imported or executed.

Emitted file validates against both:
* ``schemas/cyclonedx-bom-1.6.schema.json`` (the official CycloneDX schema), and
* ``schemas/aibom-1.0.schema.json`` (this project's stricter contract).
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agentaudit import __version__
from agentaudit.layers import static_graph as sg
from agentaudit.layers.capability_graph import analyze_capability_pairs, classify_tool
from agentaudit.layers.cloud_posture import _discover_config

_UUID_NS = uuid.UUID("6f6b7c1e-0000-4000-8000-a6e9f4c1b301")  # stable AIBOM namespace
_STDLIB = set(sys.stdlib_module_names) | {"__future__"}
_FRAMEWORK_MODULES = {"strands", "strands_tools", "strands_agents", "bedrock_agentcore"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Static extractors (ast only)
# --------------------------------------------------------------------------- #
def _git_info(agent_path: str) -> dict:
    """Best-effort, read-only git identity for the agent's repo. Never raises."""
    d = Path(agent_path).resolve().parent
    out: dict[str, str] = {}
    for key, args in (
        ("commit", ["rev-parse", "--short", "HEAD"]),
        ("commitFull", ["rev-parse", "HEAD"]),
        ("branch", ["rev-parse", "--abbrev-ref", "HEAD"]),
        ("remote", ["config", "--get", "remote.origin.url"]),
    ):
        try:
            r = subprocess.run(
                ["git", "-C", str(d), *args],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                out[key] = r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            break
    try:
        r = subprocess.run(
            ["git", "-C", str(d), "status", "--porcelain", "--", str(Path(agent_path).name)],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if r.returncode == 0:
            out["dirty"] = "true" if r.stdout.strip() else "false"
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_model(tree: ast.Module) -> dict | None:
    """Statically determine the model, if the source makes it possible.

    Handles ``Agent(model="...literal...")`` and
    ``Agent(model=BedrockModel(model_id="..."))`` / ``LiteLLMModel(model_id=...)``
    / ``AnthropicModel(model_id=...)`` etc. Returns ``None`` when the model is
    not a static literal (the common case — resolved from env / a default).
    """
    def model_from_call(call: ast.Call) -> dict | None:
        ctor = call.func.attr if isinstance(call.func, ast.Attribute) else (
            call.func.id if isinstance(call.func, ast.Name) else "")
        for kw in call.keywords:
            if kw.arg in ("model_id", "model"):
                lit = _const_str(kw.value)
                if lit:
                    return {"id": lit, "constructor": ctor, "source": f"{ctor}(model_id=...)"}
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id == "Agent")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "Agent")
        ):
            for kw in node.keywords:
                if kw.arg != "model":
                    continue
                lit = _const_str(kw.value)
                if lit:
                    return {"id": lit, "constructor": None, "source": "Agent(model='...')"}
                if isinstance(kw.value, ast.Call):
                    got = model_from_call(kw.value)
                    if got:
                        return got
    # a bare ``BedrockModel(model_id="...")`` assigned to a variable
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            if name.endswith("Model"):
                got = model_from_call(node)
                if got:
                    return got
    return None


def _extract_imports(tree: ast.Module) -> list[str]:
    """Third-party top-level module names imported by the agent (import-derived,
    not a resolved lockfile). Stdlib and the agent framework are excluded."""
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods.add(node.module.split(".")[0])
    return sorted(
        m for m in mods
        if m and m not in _STDLIB and m not in _FRAMEWORK_MODULES
    )


_MCP_CALL_HINTS = ("mcp_client", "MCPClient", "stdio_client", "streamablehttp_client",
                   "sse_client", "mcp_server")


def _extract_mcp(tree: ast.Module, deploy_cfg: dict | None) -> list[dict]:
    """MCP servers / gateways referenced in the agent source or its deploy config."""
    servers: list[dict] = []
    seen: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else node.func.id if isinstance(node.func, ast.Name) else "")
            if not name or not any(h in name for h in _MCP_CALL_HINTS):
                continue
            url = None
            for a in list(node.args) + [kw.value for kw in node.keywords]:
                s = _const_str(a)
                if s and (s.startswith("http") or s.startswith("stdio") or "/" in s):
                    url = s
                    break
            key = f"src:{name}:{url}"
            if key not in seen:
                seen.add(key)
                servers.append({"name": url or name, "kind": "mcp-server",
                                "source": "agent-source", "reference": name})

    cfg = deploy_cfg or {}
    for field in ("mcp_servers", "mcpServers", "gateways", "gateway"):
        val = cfg.get(field)
        if not val:
            continue
        items = val if isinstance(val, list) else [val]
        for it in items:
            if isinstance(it, str):
                entry = {"name": it, "kind": "mcp-gateway" if "gateway" in field else "mcp-server",
                         "source": "deploy-config"}
            elif isinstance(it, dict):
                entry = {
                    "name": it.get("name") or it.get("url") or it.get("arn") or "mcp",
                    "kind": "mcp-gateway" if "gateway" in field else "mcp-server",
                    "source": "deploy-config",
                }
                for k in ("url", "arn", "transport"):
                    if it.get(k):
                        entry[k] = it[k]
            else:
                continue
            key = f"cfg:{entry['name']}"
            if key not in seen:
                seen.add(key)
                servers.append(entry)
    return servers


# --------------------------------------------------------------------------- #
# BOM assembly
# --------------------------------------------------------------------------- #
def _props(**kw) -> list[dict]:
    """A CycloneDX propertyBag from kwargs, dropping None; lists become repeats."""
    out: list[dict] = []
    for k, v in kw.items():
        name = f"agentaudit:{k}"
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            for item in v:
                out.append({"name": name, "value": str(item)})
        elif isinstance(v, bool):
            out.append({"name": name, "value": "true" if v else "false"})
        else:
            out.append({"name": name, "value": str(v)})
    return out


def build_aibom(agent_path: str, deploy_config: str | None = None) -> dict:
    """Assemble the CycloneDX 1.6 AIBOM dict for one Strands agent."""
    path = Path(agent_path)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
    rel = str(path).replace("\\", "/")

    cfg_path = Path(deploy_config) if deploy_config else _discover_config(agent_path)
    deploy_cfg: dict | None = None
    if cfg_path and Path(cfg_path).exists():
        try:
            deploy_cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            deploy_cfg = None

    tools = sg.discover_tools(tree)
    pairs = analyze_capability_pairs(agent_path)
    model = _extract_model(tree)
    deps = _extract_imports(tree)
    mcp = _extract_mcp(tree, deploy_cfg)
    git = _git_info(agent_path)
    prompt_static = sg.extract_system_prompt(tree) is not None

    agent_name = (deploy_cfg or {}).get("agent_name") or path.stem
    agent_ref = f"agent:{agent_name}"

    components: list[dict] = []
    depends_on: list[str] = []

    # --- one component per @tool ---
    for t in tools:
        ref = f"tool:{t.name}"
        depends_on.append(ref)
        doc = (t.docstring or "").strip().splitlines()[0] if t.docstring else ""
        components.append({
            "type": "application",
            "bom-ref": ref,
            "name": t.name,
            **({"description": doc} if doc else {}),
            "properties": _props(
                componentKind="agent-tool",
                definedAt=f"{rel}:{t.line}",
                capability=sorted(classify_tool(t)),
                untrustedParam=list(t.untrusted_params),
                contextParam=sorted(t.ctx_params),
            ),
        })

    # --- model (only when statically determinable) ---
    if model:
        mref = f"model:{model['id']}"
        depends_on.append(mref)
        mc: dict = {
            "type": "machine-learning-model",
            "bom-ref": mref,
            "name": model["id"],
            "modelCard": {"modelParameters": {"task": "text-generation"}},
            "properties": _props(
                componentKind="model",
                modelSource=model["source"],
                modelConstructor=model.get("constructor"),
            ),
        }
        components.append(mc)

    # --- third-party dependencies (import-derived) ---
    for d in deps:
        ref = f"dep:{d}"
        depends_on.append(ref)
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": d,
            "properties": _props(componentKind="dependency", dependencySource="import"),
        })

    # --- MCP servers / gateways ---
    for m in mcp:
        ref = f"mcp:{m['name']}"
        depends_on.append(ref)
        comp = {
            "type": "application",
            "bom-ref": ref,
            "name": m["name"],
            "properties": _props(
                componentKind=m["kind"],
                mcpSource=m["source"],
                mcpTransport=m.get("transport"),
                mcpReference=m.get("reference"),
            ),
        }
        for k in ("url", "arn"):
            if m.get(k):
                comp.setdefault("externalReferences", []).append(
                    {"type": "other", "url": m[k]}
                )
        components.append(comp)

    # --- capability pairs -> annotations ---
    annotations: list[dict] = []
    for f in pairs:
        md = f.metadata
        ta, tb = md.get("tool_a"), md.get("tool_b")
        subjects = [f"tool:{ta}"] + ([f"tool:{tb}"] if tb and tb != ta else [])
        annotations.append({
            "bom-ref": f"cappair:{md.get('pattern')}:{ta}:{tb}",
            "subjects": subjects,
            "annotator": {"component": {
                "type": "application", "bom-ref": "agentaudit",
                "name": "AgentAudit", "version": __version__,
            }},
            "timestamp": _now(),
            "text": f"{f.title} — {f.description}",
        })

    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_UUID_NS, rel + ':' + sha)}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{
                "type": "application", "bom-ref": "agentaudit",
                "name": "AgentAudit", "version": __version__,
            }]},
            "component": {
                "type": "application",
                "bom-ref": agent_ref,
                "name": agent_name,
                "version": git.get("commit", "unversioned"),
                "description": "Strands agent — AgentAudit AIBOM",
                "properties": _props(
                    sourcePath=rel,
                    sourceSha256=sha,
                    framework="strands-agents",
                    toolCount=len(tools),
                    capabilityPairCount=len(pairs),
                    systemPromptStaticallyDeterminable=prompt_static,
                    modelStaticallyDeterminable=model is not None,
                    deployConfig=(str(cfg_path).replace("\\", "/") if deploy_cfg else None),
                    gitRemote=git.get("remote"),
                    gitCommit=git.get("commitFull"),
                    gitBranch=git.get("branch"),
                    gitWorkingTreeDirty=git.get("dirty"),
                ),
            },
        },
        "components": components,
        "dependencies": [
            {"ref": agent_ref, "dependsOn": depends_on},
        ],
    }
    if annotations:
        bom["annotations"] = annotations
    return bom


def render_aibom(agent_path: str, path: str | None = None,
                 deploy_config: str | None = None) -> str:
    text = json.dumps(build_aibom(agent_path, deploy_config), indent=2)
    if path:
        Path(path).write_text(text, encoding="utf-8")
    return text
