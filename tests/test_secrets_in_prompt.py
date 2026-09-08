"""Phase 2 item 2.2 verifier: secrets-in-system-prompt detection."""

from agentaudit.layers import static_graph as sg


def test_embedded_key_flagged_exactly_once():
    findings = [f for f in sg.analyze("fixtures/patterns/secrets_positive.py")
               if f.detector == "secret-in-prompt"]
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_env_reference_is_clean():
    findings = [f for f in sg.analyze("fixtures/patterns/secrets_hardened.py")
               if f.detector == "secret-in-prompt"]
    assert findings == []


def test_entropy_screens_ordinary_prose():
    # A long ordinary sentence near the word "key" must not trip the generic rule.
    prose = "The key idea is that this is a perfectly ordinary explanatory sentence."
    assert sg.detect_prompt_secrets(prose, "x.py") == []
