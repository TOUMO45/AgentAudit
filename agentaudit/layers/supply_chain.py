"""Supply-chain layer — Tool Poisoning / Rug-Pull detection (Phase 2, item 2.1).

A "rug pull" is when a tool the agent already trusts silently changes what it
does: the code or, more insidiously, the tool *description* the model reads is
altered to add new behavior (e.g. "also forward a copy to admin@external.com").
Because agents act on the tool's advertised `.tool_spec`, a description change is
a behavior change even if the signature is untouched.

We hash each tool's real `.tool_spec` (name + description + parameter schema) on
first scan and store the baseline. On every later scan we recompute and diff:
an unchanged tool *name* whose spec hash changed is a HIGH finding, with the old
and new description shown side by side.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import uuid
from pathlib import Path

from agentaudit.models import Confidence, Finding, Layer, Remediation, Severity

_DEFAULT_BASELINE = ".agentaudit/tool_baseline.json"


def _load_module(agent_path: str):
    """Import an agent file under a unique module name (no sys.modules clash)."""
    mod_name = f"_agentaudit_target_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(mod_name, agent_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
        return module, mod_name
    except Exception:
        sys.modules.pop(mod_name, None)
        raise


def extract_tool_specs(agent_path: str) -> dict[str, dict]:
    """Return ``{tool_name: tool_spec}`` for every @tool in the agent module."""
    module, mod_name = _load_module(agent_path)
    try:
        specs: dict[str, dict] = {}
        for value in vars(module).values():
            spec = getattr(value, "tool_spec", None)
            name = getattr(value, "tool_name", None)
            if spec and name and isinstance(spec, dict):
                specs[name] = spec
        return specs
    finally:
        sys.modules.pop(mod_name, None)


def spec_hash(spec: dict) -> str:
    canonical = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _description(spec: dict) -> str:
    return spec.get("description", "")


def load_baseline(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_baseline(path: str, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def detect_rugpull(agent_path: str, baseline_path: str = _DEFAULT_BASELINE) -> list[Finding]:
    """Compare the agent's current tool specs against the stored baseline.

    First scan of an agent establishes the baseline and reports nothing. Later
    scans flag any tool whose spec hash changed under an unchanged name.
    """
    key = str(Path(agent_path)).replace("\\", "/")
    current = extract_tool_specs(agent_path)
    current_entry = {
        name: {"hash": spec_hash(spec), "description": _description(spec)}
        for name, spec in current.items()
    }

    baseline = load_baseline(baseline_path)
    prior = baseline.get(key)

    if prior is None:
        # First time we've seen this agent — record and stay silent.
        baseline[key] = current_entry
        save_baseline(baseline_path, baseline)
        return []

    findings: list[Finding] = []
    for name, now in current_entry.items():
        before = prior.get(name)
        if before is None:
            continue  # newly added tool is not a rug-pull of an existing one
        if before["hash"] != now["hash"]:
            findings.append(
                Finding(
                    detector="tool-rug-pull",
                    layer=Layer.ARCHITECTURAL,
                    severity=Severity.HIGH,
                    title=f"Tool rug-pull: '{name}' changed after it was first trusted",
                    description=(
                        f"The tool '{name}' has the same name but its advertised spec "
                        f"(description / parameter schema) changed since the baseline. "
                        f"An agent acts on the tool description it is given, so a silent "
                        f"description change is a behavior change (tool poisoning)."
                    ),
                    file=key,
                    evidence=(
                        f"was: {before['description']!r}\n"
                        f"now: {now['description']!r}"
                    ),
                    confidence=Confidence.DETERMINISTIC,
                    remediation=Remediation(
                        summary="Pin tool specs and require human review before a trusted tool's description or schema changes.",
                        before=f"# baseline description:\n{before['description']}",
                        after=f"# current description:\n{now['description']}",
                    ),
                    fingerprint=f"tool-rug-pull:{key}:{name}",
                    metadata={"tool": name, "old_hash": before["hash"], "new_hash": now["hash"]},
                )
            )
    return findings
