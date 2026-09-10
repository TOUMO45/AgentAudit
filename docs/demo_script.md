# AgentAudit — Demo Video Script / Storyboard

**Target length: 4:30–5:00. No fake demo — every shell command below is real and
runs against committed code.**

Recording setup: terminal + browser, 1440×900, dark theme. Pre-run
`pip install -r requirements.txt && pip install -e .` off-camera (the second
registers the `agentaudit` command; without it, use `python -m agentaudit.cli`
everywhere below). Have the dashboard NOT yet started.

---

## 0:00–0:20 — The hook (talking head or slide)

> "AWS ships a red-team tool for Strands agents — but it only tests the *model*.
> It never looks at what the agent's *tools* can do together, or how it's
> deployed. That's the gap AgentAudit fills. Three layers, one signed
> scorecard, a concrete fix for every finding."

On screen: the one-liner — *"Your agent passed the demo. Did it pass the
pentest?"*

---

## 0:20–1:20 — Before: the vulnerable agent gets flagged (REAL)

Terminal:
```bash
agentaudit run --agent fixtures/vulnerable_agent.py
# fallback if not on PATH: python -m agentaudit.cli run --agent fixtures/vulnerable_agent.py
```

Narrate while it runs (~0.3s):
> "One command. It parses the agent with the stdlib AST — no LLM needed for the
> deterministic checks — runs the trust-graph analysis, the cloud-posture
> checks, and the prompt hygiene pass."

Freeze on the summary. Point at:
- `GRADE F  |  risk 100/100`
- 7 findings across **all three layers**: `idor-in-agent`, `confused-deputy`,
  `excessive-agency` (architectural); `iam-least-privilege`,
  `guardrails-attached`, `memory-encryption-ttl` (cloud);
  `overbroad-authority-in-prompt` (behavioral)
- Exit code 1 → `echo $?`

> "Non-zero exit — it drops straight into CI. And each finding ships with a
> diff-ready fix, not just a warning."

Quick scroll of `out/scorecard.html` (the signed dark scorecard) — 3 seconds.

---

## 1:20–1:55 — After: the hardened agent passes clean (REAL)

Terminal:
```bash
agentaudit run --agent fixtures/hardened_agent.py ; echo "exit=$?"
```

Freeze on:
- `GRADE A  |  risk 0/100`
- `clean -- no findings`
- `exit=0`

> "Same agent family. Every planted flaw fixed. Zero findings, exit zero. A
> security tool you can trust has to be able to *pass* — not just always fail.
> The fixtures are frozen and integrity-checked so this can't be gamed."

Optional 2s: `./guard.sh check` → `INTEGRITY OK`.

---

## 1:55–2:40 — The decisive innovation: the static trust graph (~45s, target 15s core)

Slide or code on screen: `agentaudit/layers/static_graph.py` +
`capability_graph.py`.

> "This is the part that doesn't exist anywhere else for Strands. It classifies
> what every `@tool` can actually *do* — write, reach the network, read secrets
> — and flags combinations. No single tool here is malicious:"

Show `fixtures/exfil/exfil_agent.py` briefly — `save_report`,
`get_api_credential`, `post_to_webhook`.

> "But together they're an exfiltration path: read a credential, stage it, POST
> it out. AgentAudit flags that as a CRITICAL capability pair — and generates
> an AgentCore Cedar policy that denies the egress leg to break the chain."

Show one generated `.cedar` file (`forbid(principal is AgentCore::IamEntity,
action == AgentCore::Action::"..._post_to_webhook", ...)`).

---

## 2:40–3:20 — Live org-wide scan against real AWS (~10s core, ~40s with narration)

Terminal:
```bash
PYTHONPATH=. python scripts/step3_org_scan.py
```

Point at the real `list_agent_runtimes` HTTP 200 response and the discovered
`agentauditdeploy-tvmm505Sjc` runtime.

> "This isn't a mock. It's `ListAgentRuntimes` against a real AWS account,
> region eu-north-1. It discovers every AgentCore runtime, runs the live
> posture check on each — `GetAgentRuntime` — and aggregates. Our deployed
> agent comes back with one real finding: it's running in PUBLIC network mode."

Show the `ORG AGGREGATION VERIFIED` line (6/6 arithmetic assertions).

---

## 3:20–3:55 — Multi-repo real-world validation (~10s core)

Slide: `references/real_world_findings.md`, Step 4 section.

> "We ran the static layer against real public Strands projects. In one
> Apache-licensed repo it found two unrestricted RCE tools — `exec` and `bash`
> on raw conversation input — and a write-to-S3-then-public-URL exfiltration
> pair. All three hand-verified against the source, with commit and line
> number. It also surfaced one of its own precision gaps, which we logged
> honestly rather than hiding."

---

## 3:55–4:30 — The dashboard + close

Terminal:
```bash
agentaudit dashboard    # prints the URL and auto-opens the browser
```

Browser opens to `http://127.0.0.1:8770/` (the command also prints it). Click **Run full audit** on
`vulnerable_agent.py`. Show the 3 pipeline stages resolve to RAN, the risk ring
hit F, the findings list, then the **Policy & Remediation** tab with the
generated Cedar.

> "Everything you just saw, in one console — and every number on it comes from a
> real scan. AgentAudit: the missing security layer for Strands agents."

End card: repo URL + `github.com/TOUMO45/AgentAudit`.

---

## Cutting-room notes

- If time is tight, compress 1:55–2:40 to a hard 15s: just the exfil fixture +
  one Cedar file.
- Do **not** claim live Cedar deployment or AgentCore Evaluations — those are
  Future Work (say so if asked).
- The PUBLIC-network-mode finding is genuinely correct; don't oversell it as
  critical — it's MEDIUM and the tool says so.
