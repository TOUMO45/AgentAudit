# Ground-Truth Manifest

This manifest is the **human-reviewed source of truth** for what AgentAudit must
find. The fixtures and this manifest are frozen after sign-off and protected by
`guard.sh` (charter rule 1 + success condition 5). If a detector's output ever
disagrees with this manifest, the **detector** is wrong — never edit a fixture
to make a check pass.

Legend — layers: `architectural` (static tool-trust graph), `behavioral`
(model / prompt), `cloud` (AgentCore/IAM posture).

---

## `vulnerable_agent.py` — expected: **non-zero exit, ≥3 findings, ≥2 layers**

| # | Flaw | Location | Layer | Detector id | Severity |
|---|------|----------|-------|-------------|----------|
| 1 | IDOR-in-Agent: `account_id` taken from conversation, record read with no ownership check | `fixtures/vulnerable_agent.py:35` (`get_account_balance`) | architectural | `idor-in-agent` | critical |
| 2 | Confused Deputy: untrusted `amount` forwarded into privileged ledger sink `_admin_credit_ledger` without validation | `fixtures/vulnerable_agent.py:47` (`process_refund`) | architectural | `confused-deputy` | critical |
| 3 | Excessive Agency: read-named `lookup_diagnostic` shells out via `os.system` | `fixtures/vulnerable_agent.py:63` (`lookup_diagnostic`) | architectural | `excessive-agency` | high |
| 4 | Overbroad authority in system prompt ("access ANY customer's data", "always comply", "never refuse") | `fixtures/vulnerable_agent.py:75` (`SYSTEM_PROMPT`) | behavioral | `overbroad-authority-in-prompt` | medium |
| 5 | IAM execution role grants `Action:"*"` on `Resource:"*"` | `fixtures/vulnerable_agent.deploy.json` | cloud | `iam-least-privilege` | high |
| 6 | Bedrock Guardrails not attached | `fixtures/vulnerable_agent.deploy.json` | cloud | `guardrails-attached` | high |
| 7 | AgentCore Memory: no encryption at rest and no TTL | `fixtures/vulnerable_agent.deploy.json` | cloud | `memory-encryption-ttl` | medium |

Minimum bar for success condition 1: findings 1–3 (architectural) plus at least
one of 4–7 satisfy "≥3 findings across ≥2 layers". The full expected set is all
seven.

---

## `hardened_agent.py` — expected: **exit 0, 0 findings**

Same agent family, every flaw above fixed:
- Identity resolved from `ToolContext` session; ownership enforced (`assert_owner`).
- Untrusted amount validated (`_validate_amount`, hard cap) before the sink.
- Read tool only reads.
- Least-authority system prompt with explicit refusal guidance.
- `hardened_agent.deploy.json`: scoped IAM, guardrails attached, memory encrypted + TTL.

This is the primary negative control (success condition 2).

---

## `empty_stub_agent.py` — expected: **exit 0, 0 findings (score 0/N)**

A benign minimal agent that runs the full pipeline with nothing to legitimately
flag (success condition 3). Proves the scorer is not vacuously true.

---

## Per-pattern fixtures (success condition 4)

Each positive case must be flagged by its detector; each hardened control must
produce **zero** findings of that class.

| Detector | Positive (must flag) | Hardened control (must be clean) |
|----------|----------------------|----------------------------------|
| `idor-in-agent` | `fixtures/patterns/idor_positive.py:13` | `fixtures/patterns/idor_hardened.py` |
| `confused-deputy` | `fixtures/patterns/confused_deputy_positive.py:17` | `fixtures/patterns/confused_deputy_hardened.py` |
| `excessive-agency` | `fixtures/patterns/excessive_agency_positive.py:12` | `fixtures/patterns/excessive_agency_hardened.py` |
