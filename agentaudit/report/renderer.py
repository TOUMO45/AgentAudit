"""Render a :class:`Scorecard` to the three output formats.

All three come from a single audit invocation (charter success condition 7):

* ``render_json`` — the signed JSON a CI gate consumes (exit code follows it).
* ``render_sarif`` — SARIF 2.1.0 for GitHub Code Scanning; validates against the
  official schema.
* ``render_html`` — a shareable dark security-dashboard scorecard.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agentaudit import signing
from agentaudit.models import Scorecard, Severity
from agentaudit.taxonomy import asi_2026

_TEMPLATES = Path(__file__).parent / "templates"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_json(card: Scorecard, path: str | None = None, key: bytes | str | None = None) -> str:
    payload = card.to_dict(include_signature=False)
    payload["signature"] = signing.sign(payload, key)
    card.signature = payload["signature"]
    text = json.dumps(payload, indent=2)
    if path:
        Path(path).write_text(text, encoding="utf-8")
    return text


def render_sarif(card: Scorecard, path: str | None = None) -> str:
    # One rule per distinct detector.
    rules: dict[str, dict] = {}
    results = []
    for f in card.findings:
        asi_codes = asi_2026.asi_for(f.detector)
        if f.detector not in rules:
            rule = {
                "id": f.detector,
                "name": f.detector.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {"layer": f.layer.value, "asi": asi_codes},
            }
            # SARIF 2.1.0 native taxonomy: a "relevant" relationship from this
            # rule to each OWASP-ASI-2026 taxon it maps to.
            rels = asi_2026.sarif_rule_relationships(f.detector)
            if rels:
                rule["relationships"] = rels
            elif asi_2026.is_unmapped(f.detector):
                rule["properties"]["asiUnmapped"] = asi_2026.unmapped_reason(f.detector)
            rules[f.detector] = rule
        result = {
            "ruleId": f.detector,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.description},
            "properties": {
                "severity": f.severity.value,
                "layer": f.layer.value,
                "confidence": f.confidence.value,
                "asi": asi_codes,
            },
        }
        result_taxa = asi_2026.sarif_result_taxa(f.detector)
        if result_taxa:
            result["taxa"] = result_taxa
        if f.file:
            region = {"startLine": f.line} if f.line else {"startLine": 1}
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": region,
                    }
                }
            ]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentAudit",
                        "informationUri": "https://github.com/agentaudit/agentaudit",
                        "version": card.tool_version,
                        "rules": list(rules.values()),
                        "supportedTaxonomies": [asi_2026.sarif_taxonomy_reference()],
                    }
                },
                "results": results,
                "taxonomies": [asi_2026.sarif_taxonomy_component()],
            }
        ],
    }
    text = json.dumps(sarif, indent=2)
    if path:
        Path(path).write_text(text, encoding="utf-8")
    return text


# Severity palette — verified colorblind-safe by scripts/check_palette.py
# (min pairwise CIE76 ΔE = 25.4 across protan/deuter/tritanopia).
SEVERITY_COLORS = {
    "critical": "#F0486B",
    "high": "#D9772A",
    "medium": "#F6EC72",
    "low": "#57A8F6",
    "info": "#8B97A7",
}
GRADE_COLORS = {"A": "#3FB98A", "B": "#8CC152", "C": "#F6EC72", "D": "#D9772A", "F": "#F0486B"}


def _code_snippet(file: str, line: int, radius: int = 3) -> list[dict]:
    """Return source lines around `line` (1-indexed) with the hit marked."""
    if not file or not line or not file.endswith(".py"):
        return []
    try:
        lines = Path(file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return [
        {"num": n, "text": lines[n - 1], "hit": n == line}
        for n in range(start, end + 1)
    ]


def _subject(f) -> str:
    """Short 'what is affected' label for the collapsed row."""
    md = f.metadata or {}
    if md.get("tool"):
        return md["tool"] + "()"
    if f.detector == "secret-in-prompt":
        return "system prompt"
    if f.layer.value == "cloud":
        return Path(f.file).name if f.file else "deployment"
    return Path(f.file).name if f.file else ""


def render_html(card: Scorecard, path: str | None = None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.globals["snippet"] = _code_snippet
    env.globals["subject"] = _subject
    env.globals["asi_for"] = asi_2026.asi_for
    env.globals["asi_tooltip"] = asi_2026.tooltip_for
    tmpl = env.get_template("scorecard.html.j2")
    text = tmpl.render(card=card, grade_color=GRADE_COLORS, sev_color=SEVERITY_COLORS)
    if path:
        Path(path).write_text(text, encoding="utf-8")
    return text
