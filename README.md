# AgentAudit

![AgentAudit grade](docs/agentaudit-badge.svg)

**The missing security layer for Strands agents.**

> *Your agent passed the demo. Did it pass the pentest?*

AgentAudit runs three independent layers of adversarial testing against a
[Strands](https://strandsagents.com) agent — **model behavior**,
**tool/architecture trust boundaries**, and **AWS/AgentCore deployment posture**
— and produces **one signed scorecard** with a concrete, diff-ready fix for
every finding.

It exists because the tooling gap is real. AWS ships
`strands_evals.experimental.redteam`, but it tests *model behavior only*. Generic
SAST scanners (agent-boundary-scan, Inkog, mcp-sec-scan) are framework-agnostic
and don't understand AgentCore. Nobody was checking the **tool/permission
layer** — the exact root cause behind the 2025–2026 MCP incidents (Cisco found a
vulnerability in 26% of 31,000 agent skills; Smithery.ai path-traversal exposed
3,000+ servers; ClawHavoc / CVE-2026-25253 compromised 1,000+ packages).
AgentAudit unifies all three layers, Strands-native.

---

## Project status

Full breakdown in **[STATUS.md](STATUS.md)**. In short:

- **Live-verified** (real command / API output on file): all 8 charter success
  conditions, including a live AgentCore posture check against the real deployed
  runtime ([`references/live_cloud_posture_verified.md`](references/live_cloud_posture_verified.md));
  org-wide discovery + scan across every AgentCore runtime in the account
  ([`references/live_org_wide_scan_verified.md`](references/live_org_wide_scan_verified.md));
  and Layer-2 static analysis against public Strands repos with 3 hand-verified
  true positives ([`references/real_world_findings.md`](references/real_world_findings.md)).
- **Code-complete but not live-verified** (a time-boxed call 3 days from the
  hackathon deadline, not a technical failure): Cedar policy auto-remediation
  deployed to a live AgentCore Gateway, AgentCore Evaluations integration, and
  the observability/tracing fix. Each is built, unit-tested, and committed — what
  it lacks is a live AWS run that would need new AgentCore infrastructure.

103 tests pass; `./guard.sh check` → `INTEGRITY OK`; CI green on a clean
Linux / Python 3.11 checkout.

---

## Install

```bash
python -m venv .venv
. .venv/Scripts/activate      # Windows: .venv\Scripts\Activate.ps1  |  Unix: source .venv/bin/activate
pip install -r requirements.txt
pip install -e .              # registers the `agentaudit` console command
```

Python 3.11+. Core stack: `strands-agents`, `strands-agents-evals`, `boto3`,
`jinja2` (nothing else — this is fixed by the project charter).

Every command below has two equivalent forms — the short `agentaudit ...`
(after `pip install -e .`, and only in the environment you installed it into)
and `python -m agentaudit ...`, which works from the repo root with no install
and no activated venv.

> **`agentaudit : The term 'agentaudit' is not recognized…`** — you're in a
> shell where the package's `Scripts/` dir isn't on `PATH` (venv not activated,
> or you installed into a different interpreter). Either re-activate the venv
> (`.venv\Scripts\Activate.ps1`), run `python -m pip install -e .` in the
> interpreter you're actually using, or just use `python -m agentaudit …`.

## One-command run

```bash
agentaudit run --agent fixtures/vulnerable_agent.py
# or, with no install:  python -m agentaudit run --agent fixtures/vulnerable_agent.py
```

You'll get a terminal summary plus three artifacts in `out/`:

| File | Purpose |
|------|---------|
| `scorecard.html` | shareable dark security-dashboard scorecard |
| `report.sarif`   | SARIF 2.1.0 — drops straight into GitHub Code Scanning |
| `report.signed.json` | HMAC-signed, tamper-evident; the CI gate reads this |

The process exits **non-zero** when findings meet the `--fail-on` threshold
(default `medium`), so it works as a CI gate out of the box.

### The before/after that tells the whole story

```bash
agentaudit run --agent fixtures/vulnerable_agent.py   # GRADE F, exits 1
agentaudit run --agent fixtures/hardened_agent.py     # GRADE A, exits 0
```

Same agent family; the second one has every planted flaw fixed. A security tool
you can trust must be able to *pass*, not only fail.

## What it detects

**Layer 2 — Static Tool Trust Graph (the core innovation).** Parses your agent
with the stdlib `ast`, builds a tool-trust graph, and flags patterns straight
from web-app penetration testing, mapped onto agents:

- **IDOR-in-Agent** — a tool trusts a caller-supplied `account_id`/`document_id`
  and reads a shared store with no ownership check.
- **Confused Deputy** — an untrusted parameter is forwarded, unvalidated, into a
  privileged sink.
- **Excessive Agency** — a "read-only" tool that shells out / deletes / writes.
- **SSRF-via-tool-param** — a `url`/`endpoint` parameter reaches an HTTP call
  with no allowlist.
- **Secret-in-system-prompt** — an API key / high-entropy token embedded in the
  prompt.
- **Tool rug-pull** — a trusted tool's `.tool_spec` silently changes between
  scans (supply-chain / tool-poisoning).
- **Exfiltration capability pair** — no single tool is dangerous, but the tool
  *set* combines write / read-secret / read-data with network egress. This is
  the finding [Cedar auto-remediation](agentaudit/remediation/cedar.py) is
  generated from.

**Layer 1 — Behavioral.** Static system-prompt hygiene (over-broad authority,
missing refusal guidance) plus a wrapper around AWS's own
`strands_evals.redteam` that auto-generates adversarial cases from *your agent's
actual tool list* on top of the five built-in risk categories.

**Layer 3 — Cloud Posture.** IAM least-privilege, Bedrock Guardrails
attached-and-active, and AgentCore Memory encryption/TTL — offline against a
`<agent>.deploy.json` descriptor, or live via **read-only** boto3
(`List*`/`Get*` only, never a mutating call).

## Usage

Both forms work everywhere — `agentaudit <cmd>` after `pip install -e .`, or
`python -m agentaudit <cmd>` with no install:

```bash
agentaudit run --agent path/to/agent.py \
    [--deploy-config agentcore.deploy.json] \   # else auto-discovered as <agent>.deploy.json
    [--out out/] [--no-dynamic] \
    [--live-role my-exec-role --region us-east-1] \
    [--fail-on {any,medium,high,critical}]

agentaudit verify --json out/report.signed.json   # prove a report wasn't tampered with
agentaudit dashboard [--port 8770] [--no-open]     # live web console over HTTP

# guaranteed fallback if `agentaudit` isn't on your PATH:
python -m agentaudit run --agent path/to/agent.py
python -m agentaudit dashboard
```

`agentaudit dashboard` prints its URL and auto-opens your browser to
`http://127.0.0.1:8770/` (`--no-open` to just print; it walks to the next free
port if 8770 is busy). It serves over HTTP — **never** open `ui.html` as a
`file://` path; the page shows a banner telling you so if you do. Every number
the dashboard shows comes from a real scan, and each section has an explicit
empty / unavailable state — it never renders mock data as if it were a real
result.

Live IAM check demo (works with or without AWS credentials — stubbed mode is
clearly labeled):

```bash
python scripts/live_iam_check_demo.py
```

## Ground truth & the integrity guard

The `fixtures/` set and [`fixtures/MANIFEST.md`](fixtures/MANIFEST.md) are the
human-reviewed source of truth. After sign-off they are frozen and protected:

```bash
./guard.sh freeze     # record trusted hashes of fixtures + detector/scorer code
./guard.sh check      # prove nothing changed behind the human's back (INTEGRITY OK)
```

If a check fails against a fixture, the rule is: **fix the detector, never the
fixture.** The trap logic (why each fixture can pass, not only fail) is in
[`references/trap-design.md`](references/trap-design.md).

## Testing

```bash
pytest
```

The suite encodes the charter's success conditions directly: each pattern class
flagged on its positive with zero false positives on the hardened control, the
vulnerable→fail / hardened→clean / stub→zero gates, and the three-format output
contract.

## Architecture

See [`docs/architecture.md`](docs/architecture.md).

## A note on live AWS

The cloud-posture layer's boto3 code path is real and read-only. Live checks
against a deployed AgentCore agent require AWS credentials with read-only IAM
permissions; without them, the layer degrades honestly (reported as `skipped`)
and the demo uses a **clearly labeled** stubbed IAM response that drives the
identical code path. Nothing is ever implied to be live when it is not.

## Future work

**a. Live Cedar policy enforcement via a real AgentCore Gateway.** The generator
(`agentaudit/remediation/cedar.py`) already emits schema-valid AgentCore Cedar
from a capability-pair finding, and `deploy.py` wraps the real `CreatePolicy`
API. The next step is standing up an AgentCore Gateway (needs an IAM role +
`iam:PassRole`), deploying a generated deny policy against a test runtime,
confirming `GetPolicy` reports `ACTIVE`, and demonstrating a blocked vs. allowed
tool call end-to-end. This turns AgentAudit from *report* to *enforced
remediation*.

**b. AgentCore Evaluations integration.** Run AWS's built-in evaluators
(`StartBatchEvaluation` / `GetBatchEvaluation`) alongside the custom
`strands_evals.redteam` scenarios in Layer 1, tagging each finding by origin
(`agentcore-evaluations` vs `custom-redteam`) so results carry AWS's own
framework's weight in addition to ours.

**c. Observability / unified tracing.** Resolve the two non-fatal
`logs:PutResourcePolicy` / `logs:PutDeliverySource` warnings seen at deploy by
adding the scoped `logs:` delivery permissions, setting
`UNIFIED_TRACES_DESTINATION_ENABLED=true`, and routing spans to the agent's own
CloudWatch log group.

**d. Layer 1 + Layer 2 as a bug-bounty methodology.** The behavioral layer
(adversarial cases generated from the target's real tool list) and the static
trust-graph layer (IDOR-in-agent, confused deputy, excessive agency, SSRF,
exfiltration capability pairs) are directly applicable to authorized bug-bounty
engagements on programs whose scope **explicitly covers AI / agent features** —
where the researcher can read the agent's tool definitions and system prompt.
Layer 3 (cloud posture) is **not** applicable to external black-box bounty work:
it requires the target's own read-only IAM/AgentCore access, so it only fits
direct enterprise engagements. No external target testing has been or will be
performed from this repo; this is a note on where the methodology transfers.

## License

Apache-2.0 — see [LICENSE](LICENSE).
