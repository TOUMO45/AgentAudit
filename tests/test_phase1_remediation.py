"""Phase 1 verification: capability-pair detection -> Cedar -> deploy plumbing."""

import json
from pathlib import Path

import pytest

from agentaudit.layers.capability_graph import analyze_capability_pairs, classify_tool
from agentaudit.layers.static_graph import discover_tools
from agentaudit.remediation.cedar import generate_cedar_policy, policy_name_for
from agentaudit.remediation.deploy import deploy_cedar_policy, remediate_findings

EXFIL = "fixtures/exfil/exfil_agent.py"
CLEAN = "fixtures/exfil/exfil_hardened.py"
GW_ARN = "arn:aws:bedrock-agentcore:eu-north-1:580912381651:gateway/test-gw"


# --- detection -------------------------------------------------------------
def test_write_plus_network_detected():
    pats = {f.metadata["pattern"] for f in analyze_capability_pairs(EXFIL)}
    assert "write-plus-network" in pats


def test_secret_plus_network_detected_as_critical():
    hits = [f for f in analyze_capability_pairs(EXFIL)
            if f.metadata["pattern"] == "secret-plus-network"]
    assert len(hits) == 1
    assert hits[0].severity.value == "critical"


def test_hardened_control_has_no_capability_pair():
    assert analyze_capability_pairs(CLEAN) == []


def test_capabilities_classified_correctly():
    import ast

    tree = ast.parse(Path(EXFIL).read_text(encoding="utf-8"))
    caps = {t.name: classify_tool(t) for t in discover_tools(tree)}
    assert "WRITE" in caps["save_report"]
    assert "READ_SECRET" in caps["get_api_credential"]
    assert "NETWORK" in caps["post_to_webhook"]


# --- Cedar generation ------------------------------------------------------
def test_cedar_is_schema_shaped():
    f = analyze_capability_pairs(EXFIL)[0]
    text = generate_cedar_policy(f, gateway_arn=GW_ARN)
    assert text.rstrip().endswith(";")
    assert "forbid(" in text
    assert "principal is AgentCore::IamEntity" in text
    assert 'AgentCore::Action::"' in text
    assert f'resource == AgentCore::Gateway::"{GW_ARN}"' in text


def test_cedar_denies_the_egress_leg():
    """The NETWORK tool is the leg denied — that's what breaks the chain."""
    for f in analyze_capability_pairs(EXFIL):
        text = generate_cedar_policy(f, gateway_arn=GW_ARN)
        assert 'AgentCore::Action::"AgentAudit___post_to_webhook"' in text


def test_cedar_accepts_plain_dict():
    f = analyze_capability_pairs(EXFIL)[0]
    text = generate_cedar_policy(f.to_dict(), gateway_arn=GW_ARN)
    assert "forbid(" in text


def test_policy_name_is_api_safe():
    f = analyze_capability_pairs(EXFIL)[0]
    name = policy_name_for(f)
    assert len(name) <= 64
    assert all(c.isalnum() or c in "-_" for c in name)


# --- deployment plumbing ---------------------------------------------------
def test_dry_run_writes_cedar_and_result(tmp_path):
    f = analyze_capability_pairs(EXFIL)[0]
    text = generate_cedar_policy(f, gateway_arn=GW_ARN)
    res = deploy_cedar_policy(text, gateway_id="gw", finding_id="fid-1", dry_run=True)
    assert res.status == "dry-run" and res.dry_run is True
    # default dir
    p = Path("policies/generated/fid-1.cedar")
    assert p.exists()
    assert p.read_text(encoding="utf-8") == text
    meta = json.loads(Path("policies/generated/fid-1.json").read_text(encoding="utf-8"))
    assert meta["status"] == "dry-run"


def test_only_high_and_critical_are_remediated(tmp_path):
    findings = analyze_capability_pairs(EXFIL)
    sevs = {f.severity.value for f in findings}
    results = remediate_findings(findings, GW_ARN, "gw", dry_run=True,
                                 policy_dir=tmp_path)
    remediated = len([f for f in findings if f.severity.value in ("critical", "high")])
    assert len(results) == remediated
    assert all(r.status == "dry-run" for r in results)
    # medium findings (read-plus-network) must NOT be auto-remediated
    if "medium" in sevs:
        assert len(results) < len(findings)


def test_deploy_never_raises_on_bad_input():
    """A failed live deploy returns an error result, it does not crash a scan."""
    res = deploy_cedar_policy("forbid();", gateway_id="does-not-exist",
                              finding_id="fid-err", dry_run=False,
                              policy_engine_id=None)
    assert res.status == "error"
    assert res.error
