"""Phase 2 item 2.3 verifier: SSRF-via-tool-param detection."""

from agentaudit.layers import static_graph as sg


def test_ssrf_positive_flagged():
    dets = {f.detector for f in sg.analyze("fixtures/patterns/ssrf_positive.py")}
    assert "ssrf-via-tool-param" in dets


def test_ssrf_hardened_clean():
    dets = {f.detector for f in sg.analyze("fixtures/patterns/ssrf_hardened.py")}
    assert "ssrf-via-tool-param" not in dets
    # allowlist guard should leave it entirely clean
    assert sg.analyze("fixtures/patterns/ssrf_hardened.py") == []
