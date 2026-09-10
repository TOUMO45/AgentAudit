# AgentAudit — Full Build Prompt for Coding Agent

You are the lead engineer completing **AgentAudit**, a security audit platform for
Strands agents deployed on Amazon Bedrock AgentCore. You have full permission to
read, write, and execute code in this project, and to call AWS APIs needed to
build and verify each feature below. You do **not** have permission to weaken
IAM policies broadly, delete production resources, or mark a task complete
without passing its stated verification.

**Project root:** `C:\Users\E16\agentcore-test` (or the AgentAudit repo root —
confirm the actual path before starting and use it consistently).

**AWS context:** Account `580912381651`, region `eu-north-1`. Deployed agent
runtime: `arn:aws:bedrock-agentcore:eu-north-1:580912381651:runtime/agentauditdeploy-tvmm505Sjc`.
IAM identity used for CLI/API calls: user `agentaudit`
(`arn:aws:iam::580912381651:user/agentaudit`) with inline policy
`AgentAuditInvokePolicy`.

## Non-negotiable working rules

1. **No fake completion.** A task is only "done" when its Verification section
   below passes, with real command output pasted as proof — not "should work"
   or "looks correct."
2. **No invented resources.** Never fabricate ARNs, IDs, model names, or API
   responses. If something is unknown, query it for real (AWS CLI/SDK) before
   using it.
3. **Least privilege, always.** When you hit an AccessDenied error, add the
   *specific* action + resource needed to the existing `AgentAuditInvokePolicy`
   inline policy — never attach a broad managed policy (e.g. `AdministratorAccess`,
   `AmazonBedrockFullAccess`) as a shortcut. Every new permission you request must
   be scoped to the exact ARN/resource involved.
4. **Confirm before irreversible or costly actions** (deleting resources,
   deploying to production, enabling org-wide auto-detection) — describe what
   you're about to do and why before doing it.
5. **Real data over mock data.** The dashboard currently uses mock/simulated
   scan results. Every phase below ends with replacing its mock section with a
   real, live call. Do not leave a phase "wired to fake data and called done."
6. **One phase at a time.** Complete a phase's build + verification before
   starting the next. If a phase fails verification after 3 fix attempts, stop
   and report the exact error — do not silently skip to the next phase.

---

## Phase 1 — Cedar Policy Auto-Remediation (AgentCore Policy)

**Goal:** When the static analyzer (trust-graph scan) flags a finding — e.g. a
tool combination that enables data exfiltration — AgentAudit automatically
generates a Cedar policy statement that blocks the dangerous tool-call pattern,
and pushes it to AgentCore Policy attached to the relevant AgentCore Gateway.
This turns AgentAudit from a reporting tool into an auto-remediation tool.

**Build steps:**
1. Confirm whether an AgentCore Gateway already exists for this agent. If not,
   create a minimal one for testing (document the exact CLI/API command used).
2. Write a function `generate_cedar_policy(finding: dict) -> str` that takes a
   static-analysis finding (tool names, capability pair, severity) and outputs
   a valid Cedar policy statement denying that specific tool-call sequence.
   Cover at minimum the "write + network" and "read-secret + network" patterns
   already identified as findings.
3. Write a function `deploy_cedar_policy(policy_text: str, gateway_id: str)`
   that submits the policy to AgentCore Policy via the real API (not a stub).
4. Wire this into the static analysis stage: after a HIGH or CRITICAL finding
   is produced, call `generate_cedar_policy` then `deploy_cedar_policy`
   automatically (with a dry-run flag defaulting to True until Phase 1
   verification passes, then flip to live).
5. Log every generated policy and its deployment result to a local file
   `policies/generated/<finding_id>.cedar` for audit purposes.

**Verification (must pass before marking Phase 1 done):**
- [ ] Run the static analyzer against a test agent file that intentionally
      contains a write-tool + network-tool combination.
- [ ] Confirm a `.cedar` file was generated on disk and print its contents.
- [ ] Confirm via AWS CLI/API (e.g. `aws bedrock-agentcore-control get-gateway-policy`
      or the correct real API call — verify the actual command name in AWS docs
      before using it) that the policy is attached and `ACTIVE`.
- [ ] Attempt the blocked tool-call sequence against the live agent and confirm
      the call is denied with a policy-violation error (not a crash, not a
      silent pass-through).
- [ ] Attempt an allowed, unrelated tool call and confirm it still succeeds
      (i.e. the policy is scoped, not blocking everything).

---

## Phase 2 — AWS Agent Registry Integration (org-wide scanning)

**Goal:** AgentAudit can discover and scan every AgentCore agent registered
(or auto-detected) in the AWS Agent Registry for this account/organization,
not just one hardcoded agent — turning it into an org-wide security posture
tool.

**Build steps:**
1. Check whether AWS Agent Registry is enabled for this account. If not,
   set up a registry in the `agent-registry` namespace (the GA namespace —
   confirm this is correct for the account's region before proceeding).
2. Write a function `list_registered_agents() -> list[AgentRecord]` that calls
   the real Agent Registry API and returns every agent/runtime currently known
   (approved or draft).
3. Extend the scan pipeline so "Run full audit" can target either a single
   agent ARN (current behavior) or "All registered agents" (new). For the
   latter, loop through `list_registered_agents()` and run the 3-stage pipeline
   against each, aggregating results.
4. Add a results view grouped by agent, with an org-wide summary (total
   critical/high/medium/low across all scanned agents).

**Verification:**
- [ ] `list_registered_agents()` returns the real `agentauditdeploy` agent
      (and any others actually present) — print the raw API response.
- [ ] Run an org-wide scan and confirm each agent gets its own set of findings
      (not the same findings duplicated across agents).
- [ ] Confirm the aggregate summary numbers equal the sum of per-agent numbers
      (a simple arithmetic check — write this as an actual assertion in test
      code, not a visual check).
- [ ] Test with zero agents registered (temporarily, if safe) and confirm the
      UI shows an explicit "no agents found" state rather than erroring or
      showing stale data.

---

## Phase 3 — AgentCore Evaluations Integration (behavioral stage)

**Goal:** Replace the custom-only behavioral red-team stage with AgentCore
Evaluations' built-in evaluators (helpfulness, tool selection, accuracy, etc.)
run alongside your custom security-specific redteam scenarios, so findings
carry the credibility of AWS's own evaluation framework in addition to your
own checks.

**Build steps:**
1. Confirm which of the 13 built-in evaluators apply to a security-audit
   use case (tool selection accuracy and policy-adherence-relevant ones are
   the priority — do not force-fit irrelevant ones like tone/sentiment).
2. Write `run_agentcore_evaluations(agent_arn: str) -> EvalResult` that
   triggers a real AgentCore Evaluations run against the deployed agent and
   retrieves results via the CloudWatch-backed dashboard/API.
3. Merge these results into the existing `strands_evals.redteam` findings so
   the behavioral stage's output includes both sources, clearly labeled by
   origin (`source: "agentcore-evaluations"` vs `source: "custom-redteam"`).

**Verification:**
- [ ] Trigger a real evaluation run and confirm a job ID / run ID is returned
      from AWS, not generated locally.
- [ ] Poll until the run reaches a terminal state and print the real scores.
- [ ] Confirm the merged findings list in AgentAudit's output correctly tags
      each finding's source field.
- [ ] Intentionally break the agent (e.g. remove a needed tool) and confirm
      the evaluator score drops accordingly — proving the evaluation reflects
      real behavior, not a hardcoded pass.

---

## Phase 4 — Fix Observability (Unified Traces Destination)

**Goal:** Resolve the existing X-Ray/observability warning from deployment by
switching to the agent's own CloudWatch log group for spans instead of the
shared log group.

**Build steps:**
1. Set `UNIFIED_TRACES_DESTINATION_ENABLED=true` on the `agentauditdeploy`
   runtime configuration.
2. Confirm the runtime execution role has `logs:PutResourcePolicy` for its own
   log group (add the specific scoped permission if missing, per the
   least-privilege rule above).
3. Redeploy (`agentcore launch`) and confirm the warning from the original
   deployment log no longer appears.

**Verification:**
- [ ] Invoke the agent and confirm spans now appear in
      `/aws/bedrock-agentcore/runtimes/agentauditdeploy-tvmm505Sjc-DEFAULT`
      under the `spans` stream (query via `aws logs tail` and paste real output).
- [ ] Confirm no `ValidationException` or trace-delivery warning appears in the
      deployment output.

---

## Phase 5 — Professional Dashboard UI (real data, not mock)

**Goal:** A single, polished web dashboard that shows all of the above live —
this is the primary demo surface, so it must be visually credible and fully
functional against real data, not the earlier mock HTML.

**Requirements:**
- Keep the existing 3-stage pipeline visualization (static / behavioral /
  posture) but wire each stage to its **real** backend call from Phases 1–3
  instead of the `setTimeout`-simulated progress.
- Add a 4th view: **Policy & Remediation** — shows every Cedar policy
  AgentAudit has generated and deployed (Phase 1), with status (`dry-run` /
  `active`) and a toggle to enable/disable a policy (with a confirmation step
  before any live change).
- Add an **org-wide view** (Phase 2) — a table of all scanned agents with
  their individual risk scores, sortable, with drill-down into any agent's
  full findings.
- Keep the findings list, severity tagging, and risk-score ring from the
  existing mockup — that visual design is approved, just needs real data.
- The UI must clearly distinguish **live/real** data from any placeholder —
  never silently show mock data as if it were a real scan result.
- Include a visible "last verified" timestamp per section so it's obvious the
  numbers reflect an actual run, not a cached demo state.

**Verification:**
- [ ] Load the dashboard with zero prior scans and confirm every section shows
      an honest empty state (no leftover mock numbers).
- [ ] Run a full audit end-to-end from the UI and confirm every number shown
      (findings, risk score, policy count) matches what the backend actually
      returned — cross-check at least 3 specific numbers manually against raw
      API/log output.
- [ ] Click into a generated Cedar policy from the UI and confirm its Cedar
      text matches the file on disk from Phase 1.
- [ ] Resize/test the dashboard at a typical laptop resolution and confirm no
      layout breakage (this will be presented live).

---

## Definition of Done (final acceptance)

All 5 phases must independently satisfy their Verification checklists with
pasted, real command/API output — not descriptions of expected behavior.
Report back phase by phase in this order, and stop for review after each one
before proceeding to the next.
