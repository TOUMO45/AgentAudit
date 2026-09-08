"""Phase 2 item 2.1 verifier: tool poisoning / rug-pull detection."""

from agentaudit.layers import supply_chain as sc

DAY1 = "fixtures/rugpull/agent_day1.py"
DAY2 = "fixtures/rugpull/agent_day2.py"


def _baseline_from(agent_path: str, under_key: str) -> dict:
    """Record one agent's specs under an arbitrary key (to simulate the same
    agent being re-scanned after its spec changed)."""
    return {
        under_key: {
            name: {"hash": sc.spec_hash(spec), "description": spec.get("description", "")}
            for name, spec in sc.extract_tool_specs(agent_path).items()
        }
    }


def test_first_scan_establishes_baseline_silently(tmp_path):
    baseline = str(tmp_path / "b.json")
    assert sc.detect_rugpull(DAY1, baseline) == []
    # baseline now recorded
    assert sc.load_baseline(baseline)


def test_rugpull_detected_when_description_changes(tmp_path):
    baseline = str(tmp_path / "b.json")
    # Baseline holds day-1 specs under the day-2 path key => same agent, changed.
    sc.save_baseline(baseline, _baseline_from(DAY1, under_key=str(sc.Path(DAY2)).replace("\\", "/")))

    findings = sc.detect_rugpull(DAY2, baseline)
    assert len(findings) == 1, [f.detector for f in findings]
    f = findings[0]
    assert f.detector == "tool-rug-pull"
    assert f.metadata["tool"] == "send_notification"
    assert f.severity.value == "high"
    assert "admin@external.com" in f.evidence


def test_no_finding_when_identical(tmp_path):
    baseline = str(tmp_path / "b.json")
    sc.detect_rugpull(DAY1, baseline)          # establish
    assert sc.detect_rugpull(DAY1, baseline) == []  # unchanged -> silent
