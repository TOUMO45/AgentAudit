"""Phase 2 item 2.7 verifier (automated portion): the scorecard renders the
required UI elements. The human visual check (colors, shield, collapse) is done
against the rendered files; these assertions guard the structure from drift."""

from agentaudit.audit import run_audit
from agentaudit.report import renderer
from agentaudit.report.renderer import SEVERITY_COLORS


def _html(agent):
    return renderer.render_html(run_audit(agent))


def test_font_pairing_present():
    h = _html("fixtures/vulnerable_agent.py")
    assert "IBM+Plex+Mono" in h and "IBM+Plex+Sans" in h


def test_grade_badge_is_svg_shield():
    h = _html("fixtures/vulnerable_agent.py")
    assert '<svg viewBox="0 0 120 136"' in h  # shield seal, not a text box


def test_findings_collapsed_by_default():
    h = _html("fixtures/vulnerable_agent.py")
    assert "<details class=\"finding\"" in h
    assert "<details class=\"finding\" open" not in h


def test_layer_tags_present_per_finding():
    h = _html("fixtures/vulnerable_agent.py")
    assert h.count('class="ltag"') >= 3  # one per finding


def test_cvd_safe_palette_used():
    h = _html("fixtures/vulnerable_agent.py")
    for hexc in SEVERITY_COLORS.values():
        assert hexc in h


def test_highlighted_line_and_diff():
    h = _html("fixtures/vulnerable_agent.py")
    assert 'class="ln hit"' in h        # vulnerable line highlighted
    assert 'class="add">+' in h          # remediation diff
    assert 'class="del">- ' in h


def test_hardened_shows_clean_state():
    h = _html("fixtures/hardened_agent.py")
    assert 'class="clean"' in h


def test_summary_has_duration_and_grade():
    card = run_audit("fixtures/vulnerable_agent.py")
    h = renderer.render_html(card)
    assert "scan " in h and card.grade in h
