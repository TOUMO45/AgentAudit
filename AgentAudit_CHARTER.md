# AgentAudit — Project Charter

> Claude Code reads this file at the start of every session. It is the contract.
> Do not renegotiate scope, stack, or rules below without the human explicitly
> approving the change first.

## What AgentAudit is

A security audit tool for AI agents built on the Strands Agents SDK. It runs three
independent layers of adversarial testing — model behavior, tool/architecture trust
boundaries, and AWS/AgentCore deployment posture — and outputs one signed scorecard
with concrete, diff-ready remediation for every finding.

## The one sentence that defines the product

> AgentAudit tells a Strands agent builder, with evidence and a fix, exactly where
> their agent would fail a real penetration test — not just whether it dodges a
> canned red-team prompt.

If a feature doesn't serve this sentence, it is out of scope.

## Why this exists (evidence, not opinion)

- AWS ships `strands_evals.experimental.redteam` — a real, current tool — but it
  tests **model behavior only** (5 risk categories: guideline_bypass,
  system_prompt_leak, harmful_content, data_exfiltration, excessive_agency; 4
  strategies: Crescendo, GOAT, PAIR, Sequential-Break). It does not analyze tool
  trust boundaries or cloud deployment posture.
- Industry data on the adjacent MCP ecosystem (2025–2026) shows the gap is real and
  costly: Cisco's analysis of 31,000 agent skills found at least one vulnerability
  in 26% of them; the Smithery.ai path-traversal disclosure exposed 3,000+ MCP
  servers; the ClawHavoc supply-chain incident (CVE-2026-25253) compromised over a
  thousand packages. The common root cause across all three: nobody was checking the
  **tool/permission layer**, only the model layer.
- Every existing generic scanner found (agent-boundary-scan, Inkog, Deconvolute,
  mcp-sec-scan) targets MCP/LangGraph/CrewAI generically — none are Strands-native
  and none understand AgentCore-specific configuration (Identity, Memory, Gateway,
  Guardrails-attachment).
- Conclusion: the union of (model-behavior red-teaming) + (static tool-trust-graph
  analysis) + (AgentCore/IAM posture checks), unified into one signed report, does
  not exist yet for Strands. That union is the product.

## Success definition (non-negotiable)

The project is DONE when **all 8** are true:

1. `agentaudit run --agent fixtures/vulnerable_agent.py` exits non-zero and reports
   at least 3 findings across at least 2 of the 3 layers, matching the manifest in
   `fixtures/MANIFEST.md`.
2. `agentaudit run --agent fixtures/hardened_agent.py` exits 0 and reports 0
   findings — the same fixture family with the planted flaws fixed. (Proves the
   tool can pass, not just always fail — see `references/trap-design.md` logic.)
3. `agentaudit run --agent fixtures/empty_stub_agent.py` (an agent with a scoring
   harness but zero real detection logic wired in) reports 0/N — proving the scorer
   itself can fail and isn't vacuously true.
4. The Static Tool Trust Graph Analyzer independently and correctly flags all three
   named pattern classes (IDOR-in-Agent, Confused Deputy, Excessive Agency) on their
   dedicated fixture cases, with zero false positives on the corresponding
   hardened/negative-control fixtures.
5. `guard.sh check` reports `INTEGRITY OK` on the frozen fixture set at any point
   after Phase 2 sign-off, and reports the exact tampered path/diff if a fixture or
   scorer file is modified without going through the human.
6. At least one AgentCore/IAM cloud-posture check runs against a real deployed test
   agent (not mocked) and produces a correct pass/fail, verified by the human reading
   the raw `boto3` API response, not the tool's summary of it.
7. `agentaudit run` produces all three output formats (HTML scorecard, SARIF, signed
   JSON) from a single invocation, and the SARIF file validates against the SARIF
   2.1.0 schema.
8. Submission artifacts complete: public GitHub repo (MIT or Apache 2.0, visible in
   repo root), README with setup + one-command run instructions, architecture
   diagram, ≤5-minute demo video showing the vulnerable→scan→fix→re-scan-clean
   sequence live, AWS Builder ID linked, Devpost submission fields filled.

## Scope table

| # | Capability | Type | Priority |
|---|---|---|---|
| 1 | Behavioral probe wrapper around `strands_evals.redteam`, auto-generating cases from the target agent's actual tool list | needs-judgment (LLM-scored) | critical |
| 2 | Static Tool Trust Graph Analyzer — AST parse of `@tool` defs + system prompt → flag IDOR-in-Agent | deterministic | **critical (decisive gate — see below)** |
| 3 | Static Tool Trust Graph Analyzer — Confused Deputy detection (unvalidated data flow from low-priv tool into high-priv tool) | deterministic | critical |
| 4 | Static Tool Trust Graph Analyzer — Excessive Agency detection (tool scope wider than declared purpose) | needs-judgment (heuristic + LLM tie-break) | high |
| 5 | AWS Cloud Posture Checker — IAM least-privilege check on AgentCore execution role | deterministic (boto3) | high |
| 6 | AWS Cloud Posture Checker — Bedrock Guardrails attached-and-active check | deterministic (boto3) | high |
| 7 | AWS Cloud Posture Checker — AgentCore Memory encryption/TTL check | deterministic (boto3) | medium |
| 8 | Unified Risk Scorer — dedup + weight findings across layers 1–3 | deterministic | critical |
| 9 | Report Renderer — HTML scorecard | deterministic | high |
| 10 | Report Renderer — SARIF export | deterministic | high |
| 11 | Report Renderer — signed JSON (for CI gate / exit code) | deterministic | high |
| 12 | Demo fixture pair: `vulnerable_agent.py` / `hardened_agent.py` with matching `MANIFEST.md` | ground truth, human-reviewed | critical |

## Non-negotiable engineering rules

1. `fixtures/` is READ-ONLY after human sign-off. If a check fails against a
   fixture, fix the detection logic — never loosen or edit the fixture to make it
   pass.
2. Deterministic checks (AST parsing, boto3 API checks) run and are trusted before
   anything requiring an LLM call to judge.
3. No new dependency without asking the human first. Core stack is `strands-agents`,
   `strands-agents-evals`, `boto3`, `ast` (stdlib), `jinja2` — nothing else without
   sign-off.
4. No invented Strands/AgentCore APIs. If unsure whether a method/field exists, read
   the actual installed package source (`python -c "import strands; print(strands.__file__)"`
   then inspect) before writing code against it — do not guess from training data,
   the SDK is new and changes fast.
5. Read-only on any real AWS account used for the cloud-posture layer. The tool may
   call `Describe*`/`Get*`/`List*` APIs only. It must never create, modify, or delete
   any AWS resource. This is enforced by only ever attaching read-only IAM policies
   to the credentials AgentAudit itself runs with during development.
6. Commit after every green gate.
7. If a scan against the vulnerable fixture ever comes back clean (0 findings), treat
   that as a bug in the detector, not a success — a security tool that finds nothing
   on a fixture built with planted vulnerabilities is broken by definition.

## Stack (fixed — do not renegotiate mid-build)

- Python 3.11+
- `strands-agents`, `strands-agents-evals` (official — pin exact versions once
  installed, do not assume behavior from documentation alone; verify against
  installed source per rule 4)
- `boto3` for AWS API calls (IAM, Bedrock, AgentCore control-plane)
- `ast` (stdlib) for static tool-definition parsing — no third-party static-analysis
  framework unless a specific gap is found and approved
- `jinja2` + a single static Tailwind CDN link for the HTML report — no frontend
  build step, no framework
- `bedrock-agentcore-starter-toolkit` for the one real test deployment used in
  success-condition 6
- CLI entry point via `click` or stdlib `argparse` — prefer `argparse` unless a
  concrete need for `click` appears

## Anti-goals

- AgentAudit does **not** try to replace `strands_evals.redteam` — it wraps and
  extends it. Do not reimplement Crescendo/GOAT/PAIR from scratch.
- AgentAudit does **not** attempt to support LangGraph, CrewAI, or raw MCP servers
  outside of Strands' own MCP tool integration. Strands-only, by design — this is
  the differentiation, not a limitation to apologize for.
- AgentAudit does **not** perform any live exploitation against a third party's
  production agent. All dynamic testing runs only against agents the user owns or
  the project's own fixtures.
- AgentAudit does **not** try to auto-fix code by writing directly to the user's
  repo. It proposes a diff; the human applies it. No auto-patching.
- AgentAudit does **not** need a database, auth system, or multi-user backend for
  this submission. It is a CLI + local report, not a hosted SaaS — resist the pull
  to build a hosted dashboard before the core detection is proven.

## Decisive gate

**Capability #2 (Static Tool Trust Graph Analyzer — IDOR-in-Agent detection) is the
decisive gate.** If this doesn't work convincingly, the product is reducible to "a
wrapper around AWS's own red-team tool," which already exists and is not a winning
submission. If this gate is not green by the point roughly 60% of remaining build
time has elapsed, stop all other work and put every remaining hour here.

## Scope-cut ladder (in order, if time runs out)

Ground truth (fixtures + manifest) and the integrity guard are never cut. Below
that, cut in this order:

1. Cloud Posture layer capabilities 6 and 7 (keep only capability 5, IAM
   least-privilege — it's the single most impressive check to demo).
2. SARIF export (capability 10) — keep JSON and HTML only.
3. Excessive Agency detection (capability 4) — keep IDOR-in-Agent and Confused
   Deputy only; two convincing pattern classes beat three shallow ones.
4. Full AgentCore live-deployment test (success condition 6) — fall back to a
   mocked `boto3` response with the mock clearly labeled as such in the demo, and
   say so plainly in the video rather than implying it's live.

Never cut: the fixture pair, the integrity guard, the decisive gate, or the demo
video's before/after sequence.
