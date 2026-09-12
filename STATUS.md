# AgentAudit — Submission Status

Last updated 2026-09-10, for the AWS × Strands hackathon submission
(deadline Sept 14). This document is the single source of truth for **what is
live-verified vs. code-complete-but-not-live-verified**, and why.

The split below is a **time-boxed scoping decision three days from the
deadline**, not a technical failure. Everything marked "code-complete" runs, is
tested, and is committed; what it lacks is a *live AWS run* that would need new
AgentCore infrastructure (a real Gateway, a redeploy) too risky to stand up this
close to the deadline.

---

## ✅ Live-verified (real command / API output on file)

| Item | Evidence |
|---|---|
| **Charter #1** — `vulnerable_agent.py` → exit 1, ≥3 findings / ≥2 layers | `pytest tests/test_success_conditions.py`; live run: GRADE F / 100 / 7 findings across all 3 layers |
| **Charter #2** — `hardened_agent.py` → exit 0, 0 findings | same test file; live run GRADE A |
| **Charter #3** — `empty_stub_agent.py` → 0/N | `test_cond3_empty_stub_scores_zero` |
| **Charter #4** — trust-graph flags IDOR / Confused Deputy / Excessive Agency, 0 FP on controls | `tests/test_static_graph.py` (parametrized positives + hardened controls) |
| **Charter #5** — `guard.sh check` = INTEGRITY OK; tamper → exact path/diff | run fresh this session; also enforced in CI |
| **Charter #6** — live AgentCore posture check on the real deployed runtime | [`references/live_cloud_posture_verified.md`](references/live_cloud_posture_verified.md) — `GetAgentRuntime` HTTP 200, verdict FAIL on `networkMode=PUBLIC`, raw boto3 response pasted |
| **Charter #7** — HTML + SARIF + signed JSON from one run; SARIF validates 2.1.0 | `test_cond7_three_formats_from_one_run` |
| **Phase 2 (org-wide)** — discover every AgentCore runtime, scan each, aggregate | [`references/live_org_wide_scan_verified.md`](references/live_org_wide_scan_verified.md) — `ListAgentRuntimes` HTTP 200, real agent found, aggregation 6/6 assertions pass |
| **Multi-repo Layer-2 validation** — static trust-graph against public strands repos | [`references/real_world_findings.md`](references/real_world_findings.md) — 3 hand-verified true positives in Apache-2.0 `kyopark2014/strands-agent` (RCE via `exec`, RCE via `bash`, S3 write→network exfil pair), each with commit + file + line; 1 detector-precision gap found and root-caused |
| **Dashboard** — stdlib HTTP server, all 3 pipeline stages resolve to real data | `agentaudit dashboard`; cross-checked API vs CLI (F / 100 / 7); no stage stuck on RUNNING |
| **CI** — green on a clean Linux / Python 3.11 checkout | GitHub Actions `agentaudit-ci` |

**214 tests (212 pass, 2 skipped). `guard.sh check` → INTEGRITY OK.** CI is
**green on origin/master** on a real GitHub Actions run (Linux, Python 3.11) —
the first fully-green run since before this round of work; two genuine,
environment-dependent test bugs were found and fixed to get there (see
git history: an unmocked live AWS call with no credential fallback in the
deploy-error path, and a test-harness helper that silently flattened
symlinks into regular files, so the symlink-escape test — skipped on
Windows — had never actually run before). (`agentaudit`
console script: run `python -m pip install -e .` in the interpreter you use, or
just `python -m agentaudit <cmd>` from the repo root.)

---

## 🆕 Sept-2026 enhancements (grounded in current external reality)

Four add-ons, each with a research step (real fetched sources) before any code.
Status is only what the phase's own testing actually proved.

| Phase | What landed | Verification |
|---|---|---|
| **1 — OWASP ASI 2026 mapping** ✅ | `agentaudit/taxonomy/asi_2026.py` is the single source of truth (rule_id → ASI codes). Scorecard HTML gets an `ASIxx` chip (reuses the `.ltag` pattern); SARIF gets the **native 2.1.0 taxonomy** (`runs[].taxonomies[]` OWASP-ASI-2026 with 10 taxa, per-rule `relationships` `kind:"relevant"`, per-result `taxa`); CLI appends `[ASI0x]`. 12/14 detectors mapped; `guardrails-attached` + `runtime-network-mode` in an explicit `UNMAPPED` allowlist; `memory-encryption-ttl` → ASI06 with an ADJACENT-fit caveat kept visible. Sources cross-checked (OWASP announcement + Modulos + DeepTeam) in `references/asi_2026_mapping.md`. | `tests/test_asi_taxonomy.py` (11): detector-coverage gate that fails on any unmapped future detector; SARIF validates clean against the vendored official `schemas/sarif-schema-2.1.0.json`. CLI + HTML output pasted in the phase report. |
| **3 — AIBOM export** ✅ | 4th artifact `out/aibom.json` from the same `agentaudit run`, built from the **same single `ast` parse** the Layer 2 detectors use (never imports the agent). A valid **CycloneDX 1.6** BOM: `metadata.component` = the agent (+ git provenance, sha256), one component per `@tool` with `agentaudit:capability` = the exact `classify_tool()` output, `library` components for import-derived deps, `machine-learning-model` + `modelCard` when the model is a static literal, MCP servers/gateways, and capability pairs as CycloneDX `annotations`. `references/aibom_format.md`. | `tests/test_aibom.py` (15): every emitted BOM validates against **both** the vendored official `schemas/cyclonedx-bom-1.6.schema.json` and the stricter project `schemas/aibom-1.0.schema.json`; tool/capability/pair counts cross-checked against `fixtures/MANIFEST.md`; a module that `raise`s on import still produces a full BOM. |
| **2 — CoreBreak detector (CVE-2026-18830)** ✅ *(as a static detector — not "catches CoreBreak in the wild")* | `agentaudit/layers/harness_integrity.py`, rule_id `harness-model-skip-corebreak` (CRITICAL, HEURISTIC), `ast`-only. **Detection only** — no PoC, nothing sent anywhere. Confirmed from the pinned `strands-agents==1.55.0` source that the model-skip path (`_has_tool_use_in_latest_message`, `event_loop.py:105` + `:293-297`, pasted in `references/corebreak_detector_basis.md`) is present and that AWS did **not** patch the open-source SDK. The detector flags the one thing the deployer controls: caller-supplied conversation history reaching `Agent(messages=…)` / `agent.messages` with no step that strips `toolUse`/`tool_use` blocks and no managed-InvokeHarness marker. User-facing copy never says "detects CoreBreak" — it says the SDK is affected with no upstream fix and names the two real mitigations. Fixtures `corebreak_vulnerable.py` / `corebreak_hardened.py`; `harness_integrity.py` + both fixtures added to `guard.sh` and the integrity baseline re-frozen (35 paths). | `tests/test_corebreak.py` (21): vulnerable → 1 CRITICAL, hardened → clean; **zero false positives** across the existing fixture set (`vulnerable_agent.py` still F/7, `hardened_agent.py` still A/0); mitigation variants (named sanitizer / comprehension filter / `BeforeModelCall` hook) all clear the flag; parse-only proven. |
| **4 — AgentCore Identity / Consent-Portal posture (ASI03)** ⬜ **researched, not implemented** | **Descoped for this submission** — deadline + a thin expected result (the fixture deployment has **no AgentCore Gateway**, and a consent portal attaches to a Gateway, so a live run would almost certainly return "not configured"). The research below is real and stands on its own. | — |

### Phase 4 research (kept for future work — real, not invented)

**4a — the feature is real.** Amazon Bedrock AgentCore Identity **managed Consent
Portal** launched **2026-09-04**
([AWS What's New](https://aws.amazon.com/about-aws/whats-new/2026/09/amazon-bedrock-agentcore/),
[docs: Configure a consent portal](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-consent-portal.html)).
"A hosted, AWS-managed portal that authenticates end users to an OIDC IdP and
gathers their consent before your agent accesses a downstream resource… Each
consent portal attaches to a single AgentCore Gateway and uses an OAuth2
credential provider."

**4b — real API surface** (installed `botocore 1.43.89`, service
`bedrock-agentcore-control`, apiVersion `2023-06-05`, introspected via
`session.get_service_model`): read-only ops present —
`GetConsentPortal`, `ListConsentPortals`, `GetWorkloadIdentity`,
`ListWorkloadIdentities`, `GetOauth2CredentialProvider`,
`ListOauth2CredentialProviders`, `GetApiKeyCredentialProvider`,
`ListApiKeyCredentialProviders`, `GetTokenVault`, `GetPolicy`, `GetPolicyEngine`.
The `GetAgentRuntime` response already returned for
`agentauditdeploy-tvmm505Sjc` carries `workloadIdentityDetails.workloadIdentityArn`
(the `default` directory) but **no** consent/OAuth fields — those need the calls
above.

**4c — IAM delta** (new READ-ONLY actions the `agentaudit` user lacks; current
policy has only `GetAgentRuntime` + `List*AgentRuntime*`):

| Action | Resource (narrowest the API allows — ARN patterns TBC from the service model the same way `ListAgentRuntimes` was) |
|---|---|
| `bedrock-agentcore:ListWorkloadIdentities` | likely `*` (list) |
| `bedrock-agentcore:GetWorkloadIdentity` | `…:workload-identity-directory/*` |
| `bedrock-agentcore:ListConsentPortals` | likely `*` |
| `bedrock-agentcore:GetConsentPortal` | `…:token-vault/*/consent-portal/*` |
| `bedrock-agentcore:ListOauth2CredentialProviders` | likely `*` |
| `bedrock-agentcore:GetOauth2CredentialProvider` | `…:token-vault/*/oauth2credentialprovider/*` |
| `bedrock-agentcore:GetTokenVault` | `…:token-vault/default` |

All `Get*`/`List*` — charter rule 5 (read-only) compliant.

**4d — intended check (if resumed):** in the cloud-posture layer, pull the live
identity/consent config for the deployed runtime and FAIL on: an OAuth scope
broader than the agent's tool set needs; a user-resource-accessing action not
gated by the Consent Portal (if the API exposes that as config); or
credentials/tokens with no expiry. New rule_id → ASI03. Expected real outcome on
the current fixture deployment: **"no consent portal / no OAuth credential
providers configured"** — a valid, honestly-reported finding, not a rich verdict.

---

## 🟡 Code-complete, NOT live-verified (deferred — time-boxed)

These are built, unit-tested, and committed. They are **not** run against live
AWS because doing so needs new infrastructure we chose not to stand up 3 days
out.

| Item | What exists | Why not live-verified | To finish |
|---|---|---|---|
| **Cedar policy auto-remediation** (AWS build-prompt Phase 1) | `agentaudit/remediation/cedar.py` generates schema-valid AgentCore Cedar (`AgentCore::IamEntity` / `::Action` / `::Gateway`, verified against AWS docs) from a capability-pair finding; `deploy.py` wraps the real `CreatePolicy` API with a dry-run default and writes `policies/generated/<id>.cedar` + a `.json` audit record. Dry-run path is fully exercised in `tests/test_phase1_remediation.py`. | Needs a real **AgentCore Gateway** (which requires an IAM role + `iam:PassRole`, and the `agentaudit` user cannot create roles) plus a `CreatePolicy` live call. Standing up a Gateway and attaching a deny policy to the live runtime is a redeploy-class change we won't risk pre-deadline. | Create `AgentAuditGatewayRole` + attach `infra/AgentAuditPlatformPolicy.json`; then `deploy_cedar_policy(..., dry_run=False)` against a test Gateway; confirm `GetPolicy` status `ACTIVE`; test a blocked vs. allowed tool call. |
| **AgentCore Evaluations integration** (Phase 3) | Not started. | Lower ROI than Layers 1–3 for the submission; the behavioral layer already wraps `strands_evals.redteam`. | `bedrock-agentcore` exposes `StartBatchEvaluation` / `GetBatchEvaluation` / `ListEvaluators`; wire `run_agentcore_evaluations()` and merge results with `source: "agentcore-evaluations"`. |
| **Unified traces / observability fix** (Phase 4) | Not started. | The two `logs:PutResourcePolicy` / `logs:PutDeliverySource` warnings from deploy are **non-fatal** — the runtime works, invoke works. Fixing them needs `logs:*` delivery permissions and a redeploy. | Add the scoped `logs:` delivery actions from `infra/AgentAuditPlatformPolicy.json`, set `UNIFIED_TRACES_DESTINATION_ENABLED=true`, redeploy, confirm the warning is gone and `spans` appear in the runtime log group. |
| **Live Cedar toggle in the dashboard** (Phase 5, live parts) | The dashboard's Policy & Remediation view lists every generated `.cedar` with `dry-run` / `active` status and an Enable/Disable toggle with a confirmation step. The toggle currently reports that a live change needs AgentCore Policy permissions and makes no change. | Same blocker as Phase 1 — no live Gateway/PolicyEngine. | Once Phase 1 is live, wire the toggle to `UpdatePolicy` enforcement mode. |
| **IAM least-privilege on the execution role** (charter capability #5, live) | `check_live_role()` is written and Stubber-tested; it runs `iam:List*/Get*` only. | The `agentaudit` creds lack `iam:ListRolePolicies` on the runtime role. Charter #6 is closed by the *runtime* posture check instead (see above). | Add the 5 scoped read-only `iam:` actions in `references/live_cloud_posture_verified.md`; `check_live_role` then runs unchanged. |

---

## ⬜ Charter #8 — submission artifacts (in progress)

| Artifact | Status |
|---|---|
| Public repo, Apache-2.0, README | ✅ `https://github.com/TOUMO45/AgentAudit` |
| Architecture diagram | ✅ `docs/architecture.md` |
| Demo video script | see `docs/demo_script.md` |
| Devpost text | see `docs/devpost_submission.md` |
| Record the video / link AWS Builder ID / submit on Devpost | **manual — human only** (listed in `docs/devpost_submission.md`) |
