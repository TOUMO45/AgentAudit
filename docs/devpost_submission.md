# AgentAudit — Devpost Submission Draft

Grounded only in what is built and verified (see [`STATUS.md`](../STATUS.md)).
Nothing marked "deferred" there is claimed as done here.

---

## Tagline

The missing security layer for Strands agents — three layers of adversarial
testing, one signed scorecard, a concrete fix for every finding.

## Inspiration / Problem

AWS ships `strands_evals.experimental.redteam`, and it's good — but it tests
**model behavior only**: five risk categories, four attack strategies, all
aimed at the LLM. It never analyzes what an agent's **tools** can do together,
and it never looks at the **deployment**.

That's exactly where the 2025–2026 agent-ecosystem incidents came from. Cisco's
analysis of 31,000 agent skills found a vulnerability in 26% of them. The
Smithery.ai path-traversal disclosure exposed 3,000+ MCP servers. ClawHavoc
(CVE-2026-25253) compromised over a thousand packages. The common root cause:
nobody was checking the tool / permission layer — only the model.

Generic scanners exist (agent-boundary-scan, Inkog, mcp-sec-scan) but they're
framework-agnostic and don't understand AgentCore. Nothing unified the model
layer, the tool-trust layer, and the AgentCore/IAM posture layer for Strands
specifically. AgentAudit does.

## What it does

`agentaudit run --agent your_agent.py` runs three independent layers and emits
one signed scorecard (HTML + SARIF 2.1.0 + HMAC-signed JSON) with a diff-ready
fix for every finding. Non-zero exit on failure, so it's a CI gate.

**Layer 2 — Static Tool Trust Graph (the core innovation).** Parses the agent
with the stdlib `ast`, classifies what each `@tool` can do (write / network /
read-secret / read-data), and flags patterns from web-app pentesting mapped onto
agents:
- IDOR-in-agent (a tool trusts a caller-supplied id, no ownership check)
- Confused deputy (untrusted param → privileged sink, unvalidated)
- Excessive agency (a "read-only" tool that shells out / deletes / writes)
- SSRF-via-tool-param, secret-in-system-prompt, tool rug-pull (spec drift)
- **Exfiltration capability pair** — no single tool is dangerous, but the tool
  *set* combines a staging capability with network egress. This is the finding
  that drives auto-remediation: AgentAudit generates a schema-valid AgentCore
  **Cedar** policy that forbids the egress leg and breaks the chain.

**Layer 1 — Behavioral.** Static system-prompt hygiene plus a wrapper around
AWS's own `strands_evals.redteam`, auto-generating adversarial cases from the
target agent's real tool list on top of the five built-in categories.

**Layer 3 — Cloud Posture.** Read-only boto3 (`Get*`/`List*` only) against a
real deployed AgentCore runtime: network mode, IMDSv2 enforcement, Bedrock
Guardrails attachment, Memory encryption/TTL, and IAM least-privilege on the
execution role.

Plus a stdlib-only web dashboard (`agentaudit dashboard`) that runs the whole
pipeline live — every number on it comes from a real scan, and each section has
an explicit empty/unavailable state so mock data is never shown as real.

## How we built it

- Python 3.11+, stdlib `ast` for parsing, `boto3` for AWS, `jinja2` for the
  HTML scorecard, `strands-agents` + `strands-agents-evals`. No other runtime
  dependencies — the dashboard is `http.server`, not a framework.
- Ground truth is a frozen fixture set (`vulnerable` / `hardened` / `stub` +
  per-pattern positives and hardened controls) protected by an integrity guard
  (`guard.sh`) that hashes fixtures + detector code and reports the exact
  tampered path/diff.
- Cedar generation follows the documented AgentCore Policy schema
  (`AgentCore::IamEntity` / `::Action::"<Target>___<tool>"` / `::Gateway`),
  verified against AWS docs, not guessed.
- 103 tests; CI green on a clean Linux / Python 3.11 checkout.

## What's verified live (real API output on file)

- **All 8 charter success conditions**, including a live AgentCore posture check
  against our real deployed runtime `agentauditdeploy-tvmm505Sjc`:
  `GetAgentRuntime` HTTP 200, verdict FAIL on `networkMode=PUBLIC`, raw boto3
  response saved.
- **Org-wide discovery + scan**: `ListAgentRuntimes` against a real AWS account
  (eu-north-1), every runtime discovered and posture-scanned, aggregation
  arithmetic asserted (6/6).
- **Layer-2 static analysis against public Strands repos**: 3 hand-verified
  true positives in the Apache-2.0 `kyopark2014/strands-agent` — unrestricted
  RCE via an `exec` tool, RCE via a `bash` tool, and a write-to-S3-then-public
  exfiltration pair — each cited with commit + file + line. We also found and
  documented one of the detector's own precision gaps rather than hiding it.

## Challenges

- The Strands / AgentCore SDKs are new and move fast, so every API was verified
  against installed source or AWS docs before use — no APIs invented.
- Running as an IAM user with permissions granted one denial at a time: we
  scoped every new permission to the exact ARN from the live error message,
  never a broad managed policy.
- Deploying the test agent surfaced real issues (wrong model id for the region,
  a one-shot script where AgentCore needs an HTTP server, a per-account
  Anthropic use-case form) — all diagnosed from real CloudWatch logs, not
  guessed.

## What's next (Future Work)

1. **Live Cedar enforcement** via a real AgentCore Gateway — deploy a generated
   deny policy, confirm `ACTIVE`, demo a blocked vs. allowed call end-to-end.
   (Generator and `CreatePolicy` wrapper are built and dry-run tested; needs a
   Gateway + `iam:PassRole`.)
2. **AgentCore Evaluations integration** — run AWS's built-in evaluators
   alongside the custom red-team scenarios, tagged by source.
3. **Unified tracing** — route spans to the agent's own CloudWatch log group.
4. **Layer 1 + Layer 2 as a bug-bounty methodology** for programs whose scope
   explicitly covers AI/agent features (Layer 3 needs the target's own IAM
   access, so it's for direct enterprise engagements only — not black-box
   bounty work).

## Repo

https://github.com/TOUMO45/AgentAudit — Apache-2.0. One-command run in the
README.

---

## MANUAL steps for the human (Devpost + AWS — I cannot do these)

1. **Record the demo video** (≤5 min) following `docs/demo_script.md`. Upload to
   YouTube/Vimeo, unlisted is fine, put the link in the Devpost "Video" field.
2. **Link your AWS Builder ID** in the Devpost submission (the hackathon
   requires it — Devpost → your submission → AWS Builder ID field).
3. **Fill the Devpost text fields** from the sections above (Inspiration, What
   it does, How we built it, Challenges, Accomplishments, What's next). Paste
   the "Future Work" list into "What's next".
4. **Confirm the repo is public** and the Apache-2.0 `LICENSE` is visible in the
   repo root (it is, as of this commit).
5. **Submit before the Sept 14 deadline.**

Do NOT claim live Cedar deployment, AgentCore Evaluations, or the tracing fix as
done — they're in Future Work. `STATUS.md` has the exact line.
