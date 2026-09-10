"""Phase 2 verifier: the CoreBreak model-skip detector (CVE-2026-18830).

Detection only. No PoC, no crafted message, nothing sent anywhere — the
detector is ast-parse only. Basis: references/corebreak_detector_basis.md.
"""

from __future__ import annotations

import pytest

from agentaudit.audit import run_audit
from agentaudit.layers import harness_integrity as hi
from agentaudit.taxonomy import asi_2026

VULN = "fixtures/corebreak_vulnerable.py"
HARD = "fixtures/corebreak_hardened.py"

# existing fixtures that must NOT newly trip this detector
EXISTING = [
    "fixtures/vulnerable_agent.py",
    "fixtures/hardened_agent.py",
    "fixtures/exfil/exfil_agent.py",
    "fixtures/exfil/exfil_hardened.py",
    "fixtures/empty_stub_agent.py",
    "fixtures/patterns/idor_positive.py",
    "fixtures/patterns/idor_hardened.py",
    "fixtures/patterns/confused_deputy_positive.py",
    "fixtures/patterns/ssrf_positive.py",
    "fixtures/patterns/excessive_agency_positive.py",
    "fixtures/patterns/secrets_positive.py",
]


# --------------------------------------------------------------------------- #
# (a) vulnerable flags CRITICAL, hardened is clean
# --------------------------------------------------------------------------- #
def test_vulnerable_fixture_flags_critical():
    findings = hi.analyze(VULN)
    assert len(findings) == 1
    f = findings[0]
    assert f.detector == "harness-model-skip-corebreak"
    assert f.severity.value == "critical"
    assert f.metadata["cve"] == "CVE-2026-18830"
    assert f.metadata["alias"] == "CoreBreak"
    assert f.metadata["param"] == "messages"
    assert "Agent(messages" in f.metadata["sink"]
    assert f.line > 0


def test_hardened_fixture_is_clean():
    assert hi.analyze(HARD) == []


def test_full_audit_vulnerable_surfaces_only_corebreak_here():
    card = run_audit(VULN)
    dets = {f.detector for f in card.findings}
    assert "harness-model-skip-corebreak" in dets
    # the trust-graph per-tool detectors must not false-fire on this fixture
    assert not (dets & {"idor-in-agent", "confused-deputy", "excessive-agency",
                        "ssrf-via-tool-param", "secret-in-prompt"})
    assert card.grade == "F"  # a CRITICAL finding


def test_full_audit_hardened_is_grade_a():
    card = run_audit(HARD)
    assert card.findings == []
    assert card.grade == "A"


# --------------------------------------------------------------------------- #
# (b) no regressions on the existing fixture set
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", EXISTING)
def test_no_false_positive_on_existing_fixtures(path):
    assert hi.analyze(path) == [], f"CoreBreak detector false-fired on {path}"


def test_existing_vulnerable_and_hardened_grades_unchanged():
    # vulnerable_agent.py still F with its 7 findings; hardened_agent.py still A/clean
    assert run_audit("fixtures/vulnerable_agent.py").grade == "F"
    hardened = run_audit("fixtures/hardened_agent.py")
    assert hardened.grade == "A" and hardened.findings == []


# --------------------------------------------------------------------------- #
# (c) the finding must not overclaim, and must carry the evidence
# --------------------------------------------------------------------------- #
def test_finding_text_does_not_overclaim():
    f = hi.analyze(VULN)[0]
    blob = " ".join([f.title, f.description, f.remediation.summary]).lower()
    assert "detects corebreak" not in blob
    assert "cve-2026-18830" in blob
    assert "no upstream fix" in blob or "did not change the open-source sdk" in blob
    # points at the real, mitigable alternative
    assert "invokeharness" in blob.replace(" ", "") or "invoke harness" in blob


def test_evidence_cites_param_and_sink_and_mentions_the_real_function():
    f = hi.analyze(VULN)[0]
    assert "messages" in f.evidence and "Agent(messages" in f.evidence
    assert "_has_tool_use_in_latest_message" in f.description
    assert "event_loop.py" in f.description


def test_asi_mapping_is_asi01_asi05():
    assert asi_2026.asi_for("harness-model-skip-corebreak") == ["ASI01", "ASI05"]


# --------------------------------------------------------------------------- #
# detection-only guarantees
# --------------------------------------------------------------------------- #
def test_detector_is_parse_only_never_imports_the_target(tmp_path):
    p = tmp_path / "boom.py"
    p.write_text(
        "from strands import Agent, tool\n"
        "raise SystemExit('must never import this')\n\n"
        "def handle_request(event):\n"
        "    messages = event['messages']\n"
        "    return Agent(tools=[], messages=messages)('go')\n",
        encoding="utf-8",
    )
    findings = hi.analyze(str(p))            # would abort if we imported it
    assert len(findings) == 1 and findings[0].detector == "harness-model-skip-corebreak"


def test_mitigation_variants_all_clear_the_flag(tmp_path):
    base_top = "from strands import Agent, tool\n\n"
    handler_vuln = (
        "def handle_request(event):\n"
        "    messages = event['messages']\n"
        "    return Agent(tools=[], messages=messages)('go')\n"
    )
    # sanity: the bare version DOES flag
    p0 = tmp_path / "v.py"; p0.write_text(base_top + handler_vuln, encoding="utf-8")
    assert len(hi.analyze(str(p0))) == 1

    variants = {
        "named_sanitizer":
            base_top +
            "def strip_tool_use_blocks(m):\n    return m\n\n"
            "def handle_request(event):\n"
            "    messages = strip_tool_use_blocks(event['messages'])\n"
            "    return Agent(tools=[], messages=messages)('go')\n",
        "comprehension_filter":
            base_top +
            "def handle_request(event):\n"
            "    messages = [m for m in event['messages'] if 'toolUse' not in m]\n"
            "    return Agent(tools=[], messages=messages)('go')\n",
        "before_model_call_hook":
            base_top +
            "class GuardHook:\n    def before_model_call(self, event):\n        pass\n\n"
            "def handle_request(event):\n"
            "    messages = event['messages']\n"
            "    return Agent(tools=[], messages=messages, hooks=[GuardHook()])('go')\n",
    }
    for name, src in variants.items():
        p = tmp_path / f"{name}.py"
        p.write_text(src, encoding="utf-8")
        assert hi.analyze(str(p)) == [], f"{name} should have cleared the flag"
