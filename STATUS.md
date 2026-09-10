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

**103 tests pass. `guard.sh check` → INTEGRITY OK.**

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
