"""Audit orchestrator — runs the three layers and unifies the result.

Deterministic layers (static graph, cloud posture on a config, prompt hygiene)
run and are trusted before anything requiring a model (charter rule 2). Each
layer reports its own status so a skipped layer is explicit in the scorecard.
"""

from __future__ import annotations

from agentaudit.layers import behavioral, cloud_posture, static_graph, supply_chain
from agentaudit.models import Layer, LayerReport
from agentaudit.scorer import score_findings
from agentaudit.models import Scorecard


def run_audit(
    agent_path: str,
    deploy_config: str | None = None,
    enable_dynamic: bool = True,
    live_role: str | None = None,
    region: str | None = None,
    raw_out: str | None = None,
) -> Scorecard:
    layer_reports: list[LayerReport] = []

    # Layer 2 — architectural (deterministic, the decisive gate). Runs first.
    static_findings = static_graph.analyze(agent_path)
    detail = f"static tool-trust graph: {len(static_findings)} finding(s)"

    # Supply-chain rug-pull (imports the agent; must never crash an audit).
    try:
        rug = supply_chain.detect_rugpull(agent_path)
        static_findings = static_findings + rug
        detail += f"; rug-pull baseline checked ({len(rug)} change(s))"
    except Exception as e:  # non-importable agent, etc.
        detail += f"; rug-pull skipped ({type(e).__name__})"

    layer_reports.append(
        LayerReport(Layer.ARCHITECTURAL, "ran", detail, static_findings)
    )

    # Layer 3 — cloud posture (deterministic offline / read-only live).
    cloud_report = cloud_posture.run(
        agent_path, deploy_config=deploy_config, live_role=live_role,
        region=region, raw_out=raw_out,
    )
    layer_reports.append(cloud_report)

    # Layer 1 — behavioral (deterministic prompt hygiene + optional dynamic).
    behavioral_report = behavioral.run(agent_path, enable_dynamic=enable_dynamic)
    layer_reports.append(behavioral_report)

    all_findings = []
    for lr in layer_reports:
        all_findings.extend(lr.findings)

    return score_findings(agent_path, all_findings, layer_reports)
