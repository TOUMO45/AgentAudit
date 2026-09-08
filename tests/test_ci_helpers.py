"""Phase 2 item 2.8: PR-comment and badge generators (unit-level)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import make_badge  # noqa: E402
import render_pr_comment  # noqa: E402


def test_pr_comment_has_table_and_findings():
    data = {
        "grade": "F", "score": 100, "agent_path": "a.py",
        "counts_by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        "findings": [{"severity": "critical", "layer": "architectural",
                      "detector": "idor-in-agent", "location": "a.py:5", "title": "x"}],
        "signature": {"alg": "HMAC-SHA256", "digest": "sha256:abc"},
    }
    md = render_pr_comment.render(data)
    assert "grade **F**" in md
    assert "| Sev | Layer | Detector" in md
    assert "idor-in-agent" in md


def test_pr_comment_clean_state():
    data = {"grade": "A", "score": 0, "agent_path": "a.py",
            "counts_by_severity": {}, "findings": []}
    assert "No findings" in render_pr_comment.render(data)


def test_badge_svg_reflects_grade():
    svg = make_badge.make_svg("A", 0)
    assert svg.startswith("<svg") and "grade A" in svg
    assert make_badge.GRADE_COLOR["A"] in svg
    svg_f = make_badge.make_svg("F", 100)
    assert make_badge.GRADE_COLOR["F"] in svg_f
