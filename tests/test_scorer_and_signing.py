"""Scorer (dedup + grading) and signing (round-trip + tamper) unit tests."""

from agentaudit import signing
from agentaudit.models import (
    Confidence, Finding, Layer, LayerReport, Severity,
)
from agentaudit.scorer import score_findings


def _f(detector, sev, line=1, file="a.py"):
    return Finding(detector, Layer.ARCHITECTURAL, sev, detector, "d", file=file, line=line)


def test_dedup_keeps_most_severe():
    findings = [
        _f("idor-in-agent", Severity.HIGH),
        _f("idor-in-agent", Severity.CRITICAL),  # same fingerprint, worse
    ]
    card = score_findings("a.py", findings, [])
    assert len(card.findings) == 1
    assert card.findings[0].severity is Severity.CRITICAL


def test_grade_and_score_bounds():
    clean = score_findings("a.py", [], [])
    assert clean.grade == "A" and clean.score == 0

    crit = score_findings("a.py", [_f("x", Severity.CRITICAL)], [])
    assert crit.grade == "F"

    many = score_findings(
        "a.py",
        [_f(f"d{i}", Severity.CRITICAL, line=i) for i in range(10)],
        [],
    )
    assert many.score == 100  # capped


def test_findings_sorted_most_severe_first():
    findings = [
        _f("low", Severity.LOW, line=1),
        _f("crit", Severity.CRITICAL, line=2),
        _f("med", Severity.MEDIUM, line=3),
    ]
    card = score_findings("a.py", findings, [])
    ranks = [f.severity.rank for f in card.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_sign_verify_roundtrip():
    payload = {"score": 50, "findings": [1, 2, 3]}
    payload["signature"] = signing.sign(payload, key="k")
    assert signing.verify(payload, key="k") is True


def test_tamper_is_detected():
    payload = {"score": 50}
    payload["signature"] = signing.sign(payload, key="k")
    payload["score"] = 0  # tamper
    assert signing.verify(payload, key="k") is False


def test_wrong_key_fails():
    payload = {"score": 50}
    payload["signature"] = signing.sign(payload, key="k")
    assert signing.verify(payload, key="other") is False


def test_layer_report_status_surfaced():
    card = score_findings(
        "a.py", [], [LayerReport(Layer.CLOUD, "skipped", "no creds")]
    )
    d = card.to_dict(include_signature=False)
    assert d["layer_reports"][0]["status"] == "skipped"
