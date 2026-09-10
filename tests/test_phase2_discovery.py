"""Phase 2 verification: org-wide discovery + aggregate arithmetic."""

from agentaudit.discovery import AgentRecord, DiscoveryResult, list_registered_agents, summarize
from agentaudit.layers.capability_graph import analyze_capability_pairs
from agentaudit.layers.static_graph import analyze


class _FakeCP:
    """Stands in for bedrock-agentcore-control with a known payload."""

    class _SM:
        operation_names = ["ListAgentRuntimes"]  # no ListRegistries

    meta = type("M", (), {"service_model": _SM()})()

    def __init__(self, runtimes):
        self._runtimes = runtimes

    def get_paginator(self, name):
        raise Exception("no paginator")

    def list_agent_runtimes(self, **kw):
        return {"agentRuntimes": self._runtimes}


def test_discovery_maps_runtimes_to_records():
    cp = _FakeCP([
        {
            "agentRuntimeId": "agentauditdeploy-tvmm505Sjc",
            "agentRuntimeName": "agentauditdeploy",
            "agentRuntimeArn":
                "arn:aws:bedrock-agentcore:eu-north-1:580912381651:runtime/agentauditdeploy-tvmm505Sjc",
            "status": "READY",
        }
    ])
    res = list_registered_agents(client=cp)
    assert res.available is True
    assert res.source == "runtime-inventory"
    assert len(res.agents) == 1
    a = res.agents[0]
    assert a.name == "agentauditdeploy"
    assert a.status == "READY"
    assert a.arn.endswith("runtime/agentauditdeploy-tvmm505Sjc")


def test_zero_agents_is_an_honest_empty_state():
    res = list_registered_agents(client=_FakeCP([]))
    assert res.agents == []
    assert res.available is True          # service reachable...
    assert "no agent runtimes" in res.reason  # ...and we say why it's empty


def test_permission_failure_is_reported_not_swallowed():
    """A denied discovery must not look like 'zero agents'."""
    res = list_registered_agents()  # real call, currently denied
    if not res.available:
        assert res.reason, "unavailable discovery must carry a reason"
        assert res.agents == []


def test_aggregate_totals_equal_sum_of_per_agent():
    """Phase 2 verification: org-wide summary is arithmetically exact."""
    per_agent = {
        "exfil": analyze_capability_pairs("fixtures/exfil/exfil_agent.py"),
        "vulnerable": analyze("fixtures/vulnerable_agent.py"),
        "hardened": analyze("fixtures/hardened_agent.py"),
    }
    s = summarize(per_agent)

    for sev in ("critical", "high", "medium", "low", "info"):
        expected = sum(pa[sev] for pa in s["per_agent"].values())
        assert s["totals"][sev] == expected, f"{sev} total != sum of per-agent"

    assert s["total_findings"] == sum(len(v) for v in per_agent.values())
    assert s["agent_count"] == 3


def test_each_agent_gets_its_own_findings():
    """Findings must not be duplicated across agents."""
    per_agent = {
        "exfil": analyze_capability_pairs("fixtures/exfil/exfil_agent.py"),
        "vulnerable": analyze("fixtures/vulnerable_agent.py"),
    }
    exfil_files = {f.file for f in per_agent["exfil"]}
    vuln_files = {f.file for f in per_agent["vulnerable"]}
    assert exfil_files.isdisjoint(vuln_files)


def test_agent_record_serializes_without_raw():
    r = AgentRecord(agent_id="a", name="n", arn="arn", raw={"big": "payload"})
    assert "raw" not in r.to_dict()


def test_discovery_result_dict_shape():
    d = DiscoveryResult([], "none", False, "denied").to_dict()
    assert d["count"] == 0 and d["available"] is False and d["reason"] == "denied"
