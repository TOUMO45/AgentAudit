"""Phase 1 verifier: OWASP Top 10 for Agentic Applications (2026) mapping.

Guards the single-source-of-truth taxonomy module and its three consumers
(scorecard HTML, SARIF, CLI text). Test (a) — the coverage assertion — must
fail loudly if a new detector is added to ``agentaudit/layers/`` without an
explicit ASI mapping or an explicit "unmapped" entry.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentaudit import cli
from agentaudit.audit import run_audit
from agentaudit.report import renderer
from agentaudit.taxonomy import asi_2026

LAYERS_DIR = Path(__file__).resolve().parent.parent / "agentaudit" / "layers"
_DETECTOR_RE = re.compile(r"""detector\s*=\s*["']([a-z0-9-]+)["']""")


def _all_layer_detector_ids() -> set[str]:
    ids: set[str] = set()
    for py in LAYERS_DIR.rglob("*.py"):
        ids |= set(_DETECTOR_RE.findall(py.read_text(encoding="utf-8")))
    return ids


# --------------------------------------------------------------------------- #
# (a) coverage — every detector is classified or explicitly unmapped
# --------------------------------------------------------------------------- #
def test_every_layer_detector_is_classified():
    found = _all_layer_detector_ids()
    assert found, "grep for detector=\"...\" in agentaudit/layers/ found nothing"
    known = asi_2026.known_rule_ids()
    missing = sorted(found - known)
    assert not missing, (
        "these detector rule_ids have no ASI mapping and are not in the explicit "
        f"UNMAPPED allowlist — add them to agentaudit/taxonomy/asi_2026.py: {missing}"
    )


def test_no_stale_entries_in_taxonomy():
    """Every rule_id the taxonomy claims to know must actually exist in layers/."""
    found = _all_layer_detector_ids()
    stale = sorted(asi_2026.known_rule_ids() - found)
    assert not stale, f"taxonomy references rule_ids not found in layers/: {stale}"


# --------------------------------------------------------------------------- #
# taxonomy module internal consistency
# --------------------------------------------------------------------------- #
def test_exactly_asi01_to_asi10():
    assert list(asi_2026.ASI) == [f"ASI{n:02d}" for n in range(1, 11)]
    assert asi_2026.ASI_ORDER == list(asi_2026.ASI)


def test_mappings_reference_real_codes_and_do_not_overlap():
    for rid, codes in asi_2026.RULE_ASI.items():
        assert codes, f"{rid} maps to an empty code list"
        for c in codes:
            assert c in asi_2026.ASI, f"{rid} -> unknown code {c}"
        assert len(codes) == len(set(codes)), f"{rid} has duplicate codes"
    overlap = set(asi_2026.RULE_ASI) & set(asi_2026.UNMAPPED)
    assert not overlap, f"rule_ids both mapped and unmapped: {sorted(overlap)}"


def test_adjacency_and_unmapped_reasons_are_documented():
    # the caveat the human asked to keep visible
    assert "memory-encryption-ttl" in asi_2026.ADJACENCY_NOTES
    assert "ADJACENT" in asi_2026.adjacency_note("memory-encryption-ttl").upper()
    for rid in ("guardrails-attached", "runtime-network-mode"):
        assert asi_2026.is_unmapped(rid)
        assert len(asi_2026.unmapped_reason(rid)) > 40


def test_specific_mappings_match_the_approved_table():
    assert asi_2026.asi_for("idor-in-agent") == ["ASI03", "ASI02"]
    assert asi_2026.asi_for("overbroad-authority-in-prompt") == ["ASI01", "ASI03"]
    assert asi_2026.asi_for("tool-rug-pull") == ["ASI04", "ASI06"]
    assert asi_2026.asi_for("memory-encryption-ttl") == ["ASI06"]
    assert asi_2026.asi_for("guardrails-attached") == []
    assert asi_2026.asi_for("runtime-network-mode") == []


# --------------------------------------------------------------------------- #
# (c) SARIF — native 2.1.0 taxonomy mechanism + schema validation
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def vuln_sarif():
    card = run_audit("fixtures/vulnerable_agent.py")
    return json.loads(renderer.render_sarif(card)), card


def test_sarif_has_native_owasp_asi_taxonomy(vuln_sarif):
    sarif, _ = vuln_sarif
    run = sarif["runs"][0]

    tax = run["taxonomies"][0]
    assert tax["name"] == "OWASP-ASI-2026"
    assert tax["guid"] == asi_2026.TAXONOMY_GUID
    assert tax["releaseDateUtc"] == "2025-12-09"
    assert [t["id"] for t in tax["taxa"]] == [f"ASI{n:02d}" for n in range(1, 11)]
    for t in tax["taxa"]:
        assert t["name"] and t["shortDescription"]["text"]

    assert {"name": "OWASP-ASI-2026", "guid": asi_2026.TAXONOMY_GUID} in \
        run["tool"]["driver"]["supportedTaxonomies"]

    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}

    # a mapped rule: a "relevant" relationship to a real taxon
    idor = rules["idor-in-agent"]
    kinds = [rel["kinds"] for rel in idor["relationships"]]
    assert ["relevant"] in kinds
    targets = {rel["target"]["id"] for rel in idor["relationships"]}
    assert targets == {"ASI03", "ASI02"}
    for rel in idor["relationships"]:
        tgt = rel["target"]
        assert tgt["toolComponent"] == {"name": "OWASP-ASI-2026", "guid": asi_2026.TAXONOMY_GUID}
        assert tax["taxa"][tgt["index"]]["id"] == tgt["id"]  # index resolves

    # an unmapped rule: no relationships, a stated reason instead
    g = rules["guardrails-attached"]
    assert "relationships" not in g
    assert g["properties"]["asi"] == []
    assert "cross-cutting" in g["properties"]["asiUnmapped"].lower()

    # results carry the codes + taxa refs
    for res in run["results"]:
        assert res["properties"]["asi"] == asi_2026.asi_for(res["ruleId"])
        if res["properties"]["asi"]:
            assert [t["id"] for t in res["taxa"]] == res["properties"]["asi"]


def test_sarif_validates_against_official_2_1_0_schema(vuln_sarif):
    jsonschema = pytest.importorskip("jsonschema")
    sarif, _ = vuln_sarif
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "sarif-schema-2.1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft4Validator(schema)
    errors = [
        f"{list(e.path)}: {e.message}"
        for e in validator.iter_errors(sarif)
    ]
    assert not errors, "SARIF failed official 2.1.0 schema:\n" + "\n".join(errors[:15])


# --------------------------------------------------------------------------- #
# (b) HTML + CLI render the ASI tag
# --------------------------------------------------------------------------- #
def test_html_scorecard_shows_asi_chip_reusing_ltag_pattern():
    h = renderer.render_html(run_audit("fixtures/vulnerable_agent.py"))
    assert 'class="ltag asi"' in h                     # reuses the existing chip class
    assert "ASI03" in h and "ASI02" in h
    # tooltip carries the human title
    assert "Agent Identity &amp; Privilege Abuse" in h
    # unmapped finding renders with no ASI chip
    assert h.count('class="ltag asi"') == sum(
        1 for f in run_audit("fixtures/vulnerable_agent.py").findings
        if asi_2026.asi_for(f.detector)
    )


def test_hardened_scorecard_has_no_asi_chip():
    h = renderer.render_html(run_audit("fixtures/hardened_agent.py"))
    assert 'class="ltag asi"' not in h


def test_cli_text_output_appends_asi_code(capsys, tmp_path):
    card = run_audit("fixtures/vulnerable_agent.py")
    cli._print_summary(card, tmp_path)
    out = capsys.readouterr().out
    assert "idor-in-agent [ASI03·ASI02]" in out
    # unmapped detector: rule name with no trailing [ASI..]
    assert re.search(r"guardrails-attached\s+\S*fixtures", out)
    assert "guardrails-attached [ASI" not in out
