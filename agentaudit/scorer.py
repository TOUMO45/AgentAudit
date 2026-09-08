"""Unified Risk Scorer — dedup + weight findings across all three layers.

This is what turns three independent detector streams into one verdict. It
deduplicates (the same underlying issue can surface in more than one layer),
sums severity weights into a 0–100 risk score, and assigns a letter grade. The
scoring is deterministic (charter rule 2) so the same agent always scores the
same and a CI gate is reproducible.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentaudit import __version__
from agentaudit.models import Finding, LayerReport, Scorecard, Severity


def _dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a fingerprint, keeping the most severe."""
    best: dict[str, Finding] = {}
    for f in findings:
        cur = best.get(f.fingerprint)
        if cur is None or f.severity.rank > cur.severity.rank:
            best[f.fingerprint] = f
    return list(best.values())


def _grade(score: int, has_critical: bool) -> str:
    if score == 0:
        return "A"
    if has_critical or score >= 70:
        return "F"
    if score >= 40:
        return "D"
    if score >= 20:
        return "C"
    return "B"


def score_findings(
    agent_path: str,
    findings: list[Finding],
    layer_reports: list[LayerReport],
) -> Scorecard:
    unique = _dedup(findings)
    # Most severe first, then by layer then location — stable, demo-friendly order.
    unique.sort(key=lambda f: (-f.severity.rank, f.layer.value, f.file, f.line))

    total = min(100, sum(f.severity.weight for f in unique))
    has_critical = any(f.severity is Severity.CRITICAL for f in unique)

    return Scorecard(
        agent_path=agent_path,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        findings=unique,
        layer_reports=layer_reports,
        score=total,
        grade=_grade(total, has_critical),
        tool_version=__version__,
    )
