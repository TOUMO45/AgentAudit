"""Charter success condition 4: each pattern class is flagged on its dedicated
positive fixture, with zero false positives on the hardened negative control."""

import pytest

from agentaudit.layers import static_graph as sg

POSITIVES = [
    ("fixtures/patterns/idor_positive.py", "idor-in-agent"),
    ("fixtures/patterns/confused_deputy_positive.py", "confused-deputy"),
    ("fixtures/patterns/excessive_agency_positive.py", "excessive-agency"),
]
CONTROLS = [
    "fixtures/patterns/idor_hardened.py",
    "fixtures/patterns/confused_deputy_hardened.py",
    "fixtures/patterns/excessive_agency_hardened.py",
    "fixtures/hardened_agent.py",
    "fixtures/empty_stub_agent.py",
]


@pytest.mark.parametrize("path,detector", POSITIVES)
def test_positive_is_flagged(path, detector):
    detectors = {f.detector for f in sg.analyze(path)}
    assert detector in detectors, f"{detector} not raised on {path}"


@pytest.mark.parametrize("path,detector", POSITIVES)
def test_positive_only_its_own_class(path, detector):
    detectors = {f.detector for f in sg.analyze(path)}
    assert detectors == {detector}


@pytest.mark.parametrize("path", CONTROLS)
def test_controls_have_zero_findings(path):
    assert sg.analyze(path) == [], f"false positive on hardened control {path}"


def test_vulnerable_has_all_three_classes():
    detectors = {f.detector for f in sg.analyze("fixtures/vulnerable_agent.py")}
    assert {"idor-in-agent", "confused-deputy", "excessive-agency"} <= detectors


def test_findings_point_at_manifest_lines():
    by = {f.detector: f.line for f in sg.analyze("fixtures/vulnerable_agent.py")}
    assert by["idor-in-agent"] == 35
    assert by["confused-deputy"] == 47
    assert by["excessive-agency"] == 63
