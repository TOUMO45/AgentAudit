"""Phase 3 verifier: the AIBOM (CycloneDX 1.6) export.

The AIBOM is a fourth artifact from a single ``agentaudit run``. It is built
from the same static trust-graph parse the Layer 2 detectors use — never by
importing or executing the agent — and it validates against both the official
CycloneDX 1.6 schema and this project's stricter ``schemas/aibom-1.0.schema.json``.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from agentaudit import aibom, cli
from agentaudit.layers import static_graph as sg
from agentaudit.layers.capability_graph import classify_tool

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
VULN = "fixtures/vulnerable_agent.py"
HARD = "fixtures/hardened_agent.py"
EXFIL = "fixtures/exfil/exfil_agent.py"


@pytest.fixture(scope="module")
def cdx_validator():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    schema = json.loads((SCHEMAS / "cyclonedx-bom-1.6.schema.json").read_text("utf-8"))
    spdx = referencing.Resource.from_contents(
        json.loads((SCHEMAS / "cyclonedx-spdx.schema.json").read_text("utf-8")))
    jsf = referencing.Resource.from_contents(
        json.loads((SCHEMAS / "cyclonedx-jsf-0.82.schema.json").read_text("utf-8")))
    reg = referencing.Registry().with_resources(
        [("spdx.schema.json", spdx), ("jsf-0.82.schema.json", jsf)])
    return jsonschema.Draft7Validator(schema, registry=reg)


@pytest.fixture(scope="module")
def project_validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMAS / "aibom-1.0.schema.json").read_text("utf-8"))
    return jsonschema.Draft7Validator(schema)


def _bom(path):
    return aibom.build_aibom(path)


def _tool_components(bom):
    return {
        c["name"]: c for c in bom["components"]
        if any(p == {"name": "agentaudit:componentKind", "value": "agent-tool"}
               for p in c["properties"])
    }


def _prop_values(component, name):
    return [p["value"] for p in component["properties"] if p["name"] == name]


# --------------------------------------------------------------------------- #
# fourth artifact from one run
# --------------------------------------------------------------------------- #
def test_run_emits_aibom_next_to_the_other_three(tmp_path):
    args = cli.build_parser().parse_args(
        ["run", "--agent", VULN, "--out", str(tmp_path)])
    args.func(args)
    for name in ("scorecard.html", "report.sarif", "report.signed.json", "aibom.json"):
        assert (tmp_path / name).is_file(), f"{name} not emitted"
    bom = json.loads((tmp_path / "aibom.json").read_text("utf-8"))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"


# --------------------------------------------------------------------------- #
# (b) schema validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fixture", [VULN, HARD, EXFIL])
def test_aibom_validates_against_official_cyclonedx_1_6(fixture, cdx_validator):
    errs = [f"{list(e.path)}: {e.message}" for e in cdx_validator.iter_errors(_bom(fixture))]
    assert not errs, "CycloneDX 1.6 schema:\n" + "\n".join(errs[:15])


@pytest.mark.parametrize("fixture", [VULN, HARD, EXFIL])
def test_aibom_validates_against_project_schema(fixture, project_validator):
    errs = [f"{list(e.path)}: {e.message}" for e in project_validator.iter_errors(_bom(fixture))]
    assert not errs, "aibom-1.0 schema:\n" + "\n".join(errs[:15])


# --------------------------------------------------------------------------- #
# (a) content cross-checked against fixtures/MANIFEST.md ground truth
# --------------------------------------------------------------------------- #
def test_tool_inventory_matches_manifest():
    # MANIFEST.md: vulnerable_agent.py has exactly these 3 @tool functions.
    manifest_tools = {"get_account_balance", "process_refund", "lookup_diagnostic"}
    assert set(_tool_components(_bom(VULN))) == manifest_tools
    assert set(_tool_components(_bom(HARD))) == manifest_tools  # same family, flaws fixed

    tc = _tool_components(_bom(VULN))
    # the untrusted param each planted flaw hangs off (MANIFEST flaws 1-3)
    assert _prop_values(tc["get_account_balance"], "agentaudit:untrustedParam") == ["account_id"]
    assert "amount" in _prop_values(tc["process_refund"], "agentaudit:untrustedParam")
    assert _prop_values(tc["lookup_diagnostic"], "agentaudit:untrustedParam") == ["query"]

    meta = {p["name"]: p["value"] for p in _bom(VULN)["metadata"]["component"]["properties"]}
    assert meta["agentaudit:toolCount"] == "3"
    assert meta["agentaudit:capabilityPairCount"] == "0"


@pytest.mark.parametrize("fixture", [VULN, HARD, EXFIL])
def test_capabilities_come_straight_from_the_trust_graph_engine(fixture):
    """The AIBOM must not re-derive capabilities differently from Layer 2."""
    tree = ast.parse(Path(fixture).read_text("utf-8"))
    engine = {t.name: sorted(classify_tool(t)) for t in sg.discover_tools(tree)}
    tc = _tool_components(_bom(fixture))
    assert set(tc) == set(engine)
    for name, comp in tc.items():
        assert sorted(_prop_values(comp, "agentaudit:capability")) == engine[name]


def test_capability_pairs_are_emitted_as_annotations():
    exfil = _bom(EXFIL)
    subjects = {a["bom-ref"]: set(a["subjects"]) for a in exfil["annotations"]}
    assert subjects == {
        "cappair:write-plus-network:save_report:post_to_webhook":
            {"tool:save_report", "tool:post_to_webhook"},
        "cappair:secret-plus-network:get_api_credential:post_to_webhook":
            {"tool:get_api_credential", "tool:post_to_webhook"},
    }
    # exfil deps surfaced from imports (boto3, requests); os (stdlib) excluded
    deps = {c["name"] for c in exfil["components"]
            if any(p == {"name": "agentaudit:componentKind", "value": "dependency"}
                   for p in c["properties"])}
    assert deps == {"boto3", "requests"}

    assert "annotations" not in _bom(VULN)  # no pairs -> no annotations key
    assert "annotations" not in _bom(HARD)


def test_dependencies_edge_lists_every_component():
    bom = _bom(EXFIL)
    edge = next(d for d in bom["dependencies"] if d["ref"].startswith("agent:"))
    assert set(edge["dependsOn"]) == {c["bom-ref"] for c in bom["components"]}


# --------------------------------------------------------------------------- #
# determinism + never-import guarantees
# --------------------------------------------------------------------------- #
def test_serial_number_is_content_derived_and_stable():
    a, b = _bom(VULN), _bom(VULN)
    assert a["serialNumber"] == b["serialNumber"]
    assert a["serialNumber"].startswith("urn:uuid:")
    # everything except the wall-clock timestamps is identical run-to-run
    for bom in (a, b):
        bom["metadata"]["timestamp"] = "X"
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_aibom_never_imports_or_executes_the_agent(tmp_path):
    p = tmp_path / "explodes_on_import.py"
    p.write_text(
        "from strands import Agent, tool\n"
        "raise SystemExit('importing this module must never happen')\n\n"
        "@tool\n"
        "def do_thing(target: str):\n"
        "    '''pretend tool'''\n"
        "    return target\n",
        encoding="utf-8",
    )
    bom = aibom.build_aibom(str(p))          # would abort if we imported it
    assert set(_tool_components(bom)) == {"do_thing"}
