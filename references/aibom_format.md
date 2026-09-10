# AIBOM (AI Bill of Materials) — format decision

`agentaudit run` emits a fourth artifact, **`out/aibom.json`**, alongside
`scorecard.html` / `report.sarif` / `report.signed.json`, from the same
invocation and the same single `ast` parse the Layer 2 detectors use. The agent
file is never imported or executed.

## Research: is there a published AI-BOM schema? — Yes

**CycloneDX v1.6** has a stable, widely-adopted **AI/ML-BOM** capability:

* `component.type` includes `"machine-learning-model"`, with a `modelCard`
  object (architecture, datasets, quantitative analysis, considerations).
  <https://cyclonedx.org/capabilities/mlbom/>
* Schema: `bom-1.6.schema.json` (draft-07), `$id`
  `http://cyclonedx.org/schema/bom-1.6.schema.json`.
  <https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json>
* Third-party tools already emit CycloneDX-1.6 ML-BOMs (e.g. Snyk AI-BOM:
  <https://safeguard.sh/resources/blog/how-snyk-ai-bom-generates-a-cyclonedx-v16-compliant-ml-bom>).

**Decision:** emit a valid **CycloneDX 1.6** BOM and align every field to it, so
the file drops into existing SBOM tooling — rather than invent a bespoke schema.

## What maps cleanly to CycloneDX, and what needed `agentaudit:` properties

| AgentAudit concept | CycloneDX 1.6 encoding |
|---|---|
| the agent itself | `metadata.component` — `type: "application"`, `bom-ref: "agent:<name>"`, `version` = git short SHA |
| AgentAudit (the generator) | `metadata.tools.components[]` |
| each `@tool` | a `components[]` entry, `type: "application"`, `bom-ref: "tool:<name>"`, `description` = docstring first line |
| a statically-determinable model | `components[]`, `type: "machine-learning-model"`, `bom-ref: "model:<id>"`, minimal `modelCard.modelParameters.task = "text-generation"` |
| third-party dependency (import-derived) | `components[]`, `type: "library"`, `bom-ref: "dep:<module>"` |
| MCP server / gateway (source or deploy config) | `components[]`, `type: "application"`, `bom-ref: "mcp:<name>"`, endpoint under `externalReferences` |
| agent → {tools, model, deps, mcp} | `dependencies[]` edge from `agent:<name>` |
| **exfiltration capability pair** | `annotations[]` — `subjects` = the two `tool:` bom-refs, `annotator.component` = AgentAudit, `text` = the finding title + description |
| **per-tool capability class** (`NETWORK`/`WRITE`/`READ_SECRET`/`READ_DATA`) | `component.properties[]` `agentaudit:capability` (repeated) — CycloneDX has no native "what can this tool reach" field |
| untrusted / context parameters, source `file:line`, sha256, framework, git provenance, "model statically determinable?" | `component.properties[]` with an `agentaudit:` namespace |

Every AgentAudit-specific fact lives in a **namespaced `properties` bag** or an
`annotation` — no non-standard top-level keys — so the file stays a conformant
CycloneDX 1.6 BOM.

## Data provenance (reuse, not re-parse)

All of it comes from **one `ast.parse`** and the existing engine:

* tools, `file:line`, untrusted/context params — `static_graph.discover_tools`
* per-tool capability class — `capability_graph.classify_tool` (the *same*
  function Layer 2 uses; a test asserts the AIBOM values equal it exactly)
* capability pairs — `capability_graph.analyze_capability_pairs`
* system-prompt determinability — `static_graph.extract_system_prompt`
* model — a small local `Agent(model=…)` / `*Model(model_id=…)` literal reader
  (returns nothing when the model is resolved from env / a default — reported
  honestly as `agentaudit:modelStaticallyDeterminable = false`)
* dependencies — top-level + function-level `import` names, minus
  `sys.stdlib_module_names` and the `strands*` framework (import-derived, **not**
  a resolved lockfile — stated in the property `agentaudit:dependencySource = import`)
* deploy config — the same `<agent>.deploy.json` the cloud-posture layer
  auto-discovers

`serialNumber` is `urn:uuid:` + a UUIDv5 over `sourcePath + ":" + sha256`, so
re-running on unchanged source produces a byte-identical BOM (only
`metadata.timestamp` varies).

## Validation

`tests/test_aibom.py` validates every emitted BOM against **both**:

1. `schemas/cyclonedx-bom-1.6.schema.json` — the official CycloneDX schema
   (draft-07, with `spdx.schema.json` / `jsf-0.82.schema.json` resolved from
   vendored copies via a `referencing.Registry`).
2. `schemas/aibom-1.0.schema.json` — this project's stricter contract: pins
   `bomFormat`/`specVersion`, the `urn:uuid:` serial, the required
   `agentaudit:` metadata properties (incl. a `^[0-9a-f]{64}$` sha256), the
   `bom-ref` prefixes, and the allowed `agentaudit:componentKind` values.

Plus content cross-checks against `fixtures/MANIFEST.md` ground truth and a test
that a module which `raise`s on import still produces a full BOM (proving the
agent is parsed, never executed).
