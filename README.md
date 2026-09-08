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

## Install

```bash
python -m venv .venv
. .venv/Scripts/activate      # Windows: .venv\Scripts\Activate.ps1  |  Unix: source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.11+. Core stack: `strands-agents`, `strands-agents-evals`, `boto3`,
`jinja2` (nothing else — this is fixed by the project charter).

## One-command run

```bash
python -m agentaudit run --agent fixtures/vulnerable_agent.py
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
python -m agentaudit run --agent fixtures/vulnerable_agent.py   # GRADE F, exits 1
python -m agentaudit run --agent fixtures/hardened_agent.py     # GRADE A, exits 0
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

**Layer 1 — Behavioral.** Static system-prompt hygiene (over-broad authority,
missing refusal guidance) plus a wrapper around AWS's own
`strands_evals.redteam` that auto-generates adversarial cases from *your agent's
actual tool list* on top of the five built-in risk categories.

**Layer 3 — Cloud Posture.** IAM least-privilege, Bedrock Guardrails
attached-and-active, and AgentCore Memory encryption/TTL — offline against a
`<agent>.deploy.json` descriptor, or live via **read-only** boto3
(`List*`/`Get*` only, never a mutating call).

## Usage

```bash
agentaudit run --agent path/to/agent.py \
    [--deploy-config agentcore.deploy.json] \   # else auto-discovered as <agent>.deploy.json
    [--out out/] [--no-dynamic] \
    [--live-role my-exec-role --region us-east-1] \
    [--fail-on {any,medium,high,critical}]

agentaudit verify --json out/report.signed.json   # prove a report wasn't tampered with
```

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

## License

Apache-2.0 — see [LICENSE](LICENSE).
