"""Phase 2 item 2.4: the regression corpus enforces itself.

Cases are discovered from ``fixtures/regression/manifest.json`` at collection
time, so adding a case (via scripts/add_regression_case.py) increases the test
count automatically — no edits to this file are ever needed per new case.
"""

import json
from pathlib import Path

import pytest

from agentaudit.layers import static_graph

CORPUS = Path("fixtures/regression")
MANIFEST = CORPUS / "manifest.json"


def _cases():
    if not MANIFEST.exists():
        return []
    return json.loads(MANIFEST.read_text(encoding="utf-8")).get("cases", [])


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["file"])
def test_regression_case_behavior_locked(case):
    path = CORPUS / case["file"]
    assert path.exists(), f"missing regression fixture {path}"
    got = sorted({f.detector for f in static_graph.analyze(str(path))})
    assert got == case["expected_detectors"], (
        f"{case['file']} drifted: expected {case['expected_detectors']}, got {got}"
    )
