"""End-to-end checks for charter success conditions 1, 2, 3 and 7."""

import json

from agentaudit.audit import run_audit
from agentaudit.cli import _should_fail
from agentaudit.report import renderer


def test_cond1_vulnerable_fails_with_multi_layer_findings():
    card = run_audit("fixtures/vulnerable_agent.py")
    assert len(card.findings) >= 3
    assert card.layers_with_findings() >= 2
    assert _should_fail(card, "medium") is True  # non-zero exit


def test_cond2_hardened_is_clean():
    card = run_audit("fixtures/hardened_agent.py")
    assert card.findings == []
    assert card.grade == "A"
    assert _should_fail(card, "medium") is False  # exit 0


def test_cond3_empty_stub_scores_zero():
    card = run_audit("fixtures/empty_stub_agent.py")
    assert card.findings == []
    assert card.score == 0


def test_cond7_three_formats_from_one_run(tmp_path):
    card = run_audit("fixtures/vulnerable_agent.py")
    j = renderer.render_json(card, str(tmp_path / "r.json"), key="test-key")
    s = renderer.render_sarif(card, str(tmp_path / "r.sarif"))
    h = renderer.render_html(card, str(tmp_path / "r.html"))

    payload = json.loads(j)
    assert payload["tool"] == "agentaudit"
    assert "signature" in payload and payload["signature"]["alg"] == "HMAC-SHA256"

    sarif = json.loads(s)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgentAudit"
    for result in sarif["runs"][0]["results"]:
        assert result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]

    assert "AgentAudit" in h and card.grade in h
