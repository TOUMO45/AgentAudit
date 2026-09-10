# OWASP Top 10 for Agentic Applications (2026) — detector mapping

**Framework:** OWASP Top 10 for Agentic Applications, published **2025-12-09** by
the OWASP GenAI Security Project (OWASP Foundation).

**Single source of truth in code:** [`agentaudit/taxonomy/asi_2026.py`](../agentaudit/taxonomy/asi_2026.py).
The scorecard HTML, the SARIF export and the CLI text output all read their ASI
data from that one module — no ASI code is hard-coded anywhere else.

## Sources for the category definitions

The one-line ASI definitions used in `asi_2026.py` are **cross-checked across
three independent public renderings**, which agree:

1. OWASP GenAI Security Project — launch announcement (2025-12-09):
   <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>
2. Modulos Governance Guide — "OWASP Top 10 for Agentic Applications (2026)":
   <https://docs.modulos.ai/frameworks/owasp-top-10-agentic>
3. DeepTeam docs — "OWASP Top 10 for Agents 2026":
   <https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications>

> The authoritative OWASP PDF (linked from
> <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>)
> serves only a download link, not HTML body text, so the full per-category
> paragraphs were not machine-fetched. If those are pulled later, tighten the
> `describe()` strings in `asi_2026.py` and the justification quotes below —
> the *code → ASI* assignments themselves do not change.

## ASI01–ASI10 (as encoded)

| Code | Title |
|------|-------|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI03 | Agent Identity & Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

## Detector → ASI (14 current `rule_id`s — 12 mapped, 2 explicitly unmapped)

`rule_id`s enumerated by `grep -rn 'detector="' agentaudit/layers/` (not from
memory). A test — `tests/test_asi_taxonomy.py::test_every_layer_detector_is_classified`
— fails loudly if a future detector is added without an entry here.

| rule_id | primary | secondary | justification (against the encoded ASI definition) |
|---------|---------|-----------|----------------------------------------------------|
| `idor-in-agent` | ASI03 | ASI02 | "trust assumptions lead to unauthorized actions" — a caller-supplied id drives a read of another principal's record with no ownership check. |
| `harness-model-skip-corebreak` | ASI01 | ASI05 | CoreBreak / CVE-2026-18830: a caller-supplied `toolUse` block in the latest message makes the event loop "pursue unintended objectives … through … instruction injection" with the model never running (ASI01); the injected tool call then executes with attacker-chosen arguments outside model mediation (ASI05). See `references/corebreak_detector_basis.md`. |
| `confused-deputy` | ASI02 | ASI05 | "agents misusing … tools … causing harmful side effects despite having valid permissions"; ASI05 when the privileged sink is `exec`/`subprocess`. |
| `ssrf-via-tool-param` | ASI02 | ASI03 | a `url`/`endpoint` tool parameter drives an HTTP call to an unintended destination; ASI03 when it reaches the instance metadata / credential endpoints. |
| `excessive-agency` | ASI02 | ASI05 | "excessive execution" — a read-named tool shells out / deletes / writes; ASI05 for the `os.system`/`subprocess` path. |
| `secret-in-prompt` | ASI03 | — | ASI03 explicitly covers "leaked credentials [that] let the agent operate beyond its authorized scope" — a hard-coded key in the system prompt is exactly that. |
| `exfiltration-capability-pair` | ASI02 | ASI03 | textbook "unsafe **composition**" — the tool *set* combines write/read-secret/read-data with network egress; ASI03 for the `READ_SECRET + NETWORK` (credential-exfil) variant. |
| `tool-rug-pull` | ASI04 | ASI06 | "compromise of external … tools, schemas … that agents dynamically trust or import"; ASI06 because the tool **description the model reads** is the mutated state. |
| `overbroad-authority-in-prompt` | ASI01 | ASI03 | an over-broad prompt ("access ANY customer's data", "never refuse") removes the guidance that keeps the agent on-goal, widening the goal-hijack surface; ASI03 for the raw privilege grant. *(This mapping is the most debatable of the set — see note.)* |
| `iam-least-privilege` | ASI03 | — | `Action:"*"` on `Resource:"*"` is over-broad delegated authority — the core of ASI03. |
| `runtime-imdsv2` | ASI03 | ASI02 | IMDSv1 reachable → SSRF → instance-role credential theft → agent operates beyond scope (ASI03); pairs with `ssrf-via-tool-param` (ASI02). |
| `memory-encryption-ttl` | ASI06 | — | **ADJACENT fit.** Mapped to ASI06 for the "leakage of contextual state" half of the definition. Kept with the caveat visible in `asi_2026.ADJACENCY_NOTES` and in the module docstring: unencrypted / un-expiring agent memory is *also* a generic data-at-rest issue not unique to agentic systems. |

## Deliberately UNMAPPED (`asi_2026.UNMAPPED`)

Forcing either of these into a category would overstate the fit. They still
appear in the scorecard/SARIF/CLI — just without an ASI chip, and with a stated
reason in `properties.asiUnmapped` in the SARIF.

| rule_id | why not mapped |
|---------|----------------|
| `guardrails-attached` | **Cross-cutting mitigation.** Bedrock Guardrails defend against ASI01, ASI05 and harmful-content *simultaneously*. The absence of a defense-in-depth control is not itself an instance of one ASI category. |
| `runtime-network-mode` | **Infrastructure posture.** An AgentCore runtime exposed with `networkMode=PUBLIC` is a cloud-network hardening finding, not one of the ten agent-centric risk classes. Mapping it to ASI03/ASI08 would overstate the fit. |

## Note on `overbroad-authority-in-prompt`

ASI01 as written describes an *adversary* actively redirecting the agent. An
over-broad system prompt is a *latent* weakness that makes such redirection
easier, rather than an attack in progress. It is mapped ASI01-primary because
that is the risk it most directly enables, with ASI03 secondary for the
privilege angle; a reviewer who prefers ASI03-primary would not be wrong. The
assignment lives in one dict (`asi_2026.RULE_ASI`) and is a one-line change.

## SARIF encoding

`report.sarif` uses the **SARIF 2.1.0 native taxonomy mechanism**, not free-text
labels:

* `runs[0].taxonomies[0]` — an `OWASP-ASI-2026` `toolComponent` with a `taxa`
  entry (`id`, `name`, `shortDescription`) for each of ASI01–ASI10.
* `runs[0].tool.driver.supportedTaxonomies` — references that component.
* each mapped rule in `tool.driver.rules[]` carries `relationships[]` with
  `kinds: ["relevant"]` pointing at its taxon(s) (`reportingDescriptorReference`
  with `id` + `index` + `toolComponent`).
* each result also carries `taxa[]` (the same references) and a
  `properties.asi` string array for easy consumption; unmapped rules carry
  `properties.asiUnmapped` with the reason.

The emitted file validates clean against the official
`schemas/sarif-schema-2.1.0.json` (OASIS, errata01) via
`jsonschema.Draft4Validator` — see
`tests/test_asi_taxonomy.py::test_sarif_validates_against_official_2_1_0_schema`.
