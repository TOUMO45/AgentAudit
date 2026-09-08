# AgentAudit — Architecture

One CLI invocation fans out to three independent layers, unifies their findings
in a deterministic scorer, signs the result, and renders it three ways.

```mermaid
flowchart TD
    CLI["agentaudit run --agent &lt;file&gt;"] --> ORCH[Audit Orchestrator]

    ORCH --> L2["Layer 2 · Static Tool Trust Graph<br/>(ast parse of @tool defs + system prompt)<br/><b>DECISIVE GATE</b>"]
    ORCH --> L1["Layer 1 · Behavioral<br/>(prompt hygiene + strands_evals.redteam)"]
    ORCH --> L3["Layer 3 · Cloud Posture<br/>(boto3 IAM / Bedrock / AgentCore, read-only)"]

    L2 --> IDOR[IDOR-in-Agent]
    L2 --> CD[Confused Deputy]
    L2 --> EA[Excessive Agency]

    L1 --> B1[overbroad-authority-in-prompt]
    L3 --> C1[iam-least-privilege]
    L3 --> C2[guardrails-attached]
    L3 --> C3[memory-encryption-ttl]

    IDOR --> SCORE
    CD --> SCORE
    EA --> SCORE
    B1 --> SCORE
    C1 --> SCORE
    C2 --> SCORE
    C3 --> SCORE

    SCORE["Unified Risk Scorer<br/>dedup · weight · grade"] --> SIGN[HMAC-SHA256 Signer]
    SIGN --> R1[HTML Scorecard]
    SIGN --> R2["SARIF 2.1.0<br/>(GitHub Code Scanning)"]
    SIGN --> R3["Signed JSON<br/>(CI gate · exit code)"]
```

## Data flow

1. **Orchestrator** (`agentaudit/audit.py`) runs deterministic layers first
   (charter rule 2). Each layer returns a `LayerReport` with an explicit
   `ran` / `skipped` / `error` status so a skipped layer is never silently
   dropped from the verdict.
2. Every layer emits `Finding` objects sharing one vocabulary
   (`agentaudit/models.py`): detector id, layer, severity, evidence, and a
   diff-ready `Remediation`.
3. The **scorer** (`agentaudit/scorer.py`) deduplicates by fingerprint, sums
   severity weights into a 0–100 risk score, and assigns a letter grade —
   deterministically, so a CI gate is reproducible.
4. The **signer** (`agentaudit/signing.py`) HMACs a canonical serialization so
   the JSON report is tamper-evident.
5. The **renderers** (`agentaudit/report/`) emit all three formats from the one
   scorecard.

## Why the layers are independent

Each layer answers a different question and fails independently:

| Layer | Question | Determinism |
|-------|----------|-------------|
| Architectural | Do the tool trust boundaries hold? | deterministic (`ast`) |
| Behavioral | Does the model resist adversarial pressure? | heuristic + LLM |
| Cloud | Is the deployment posture least-privilege? | deterministic (`boto3`) |

The architectural layer is the **decisive gate**: it is the capability no
existing Strands/AgentCore tool provides, and it runs fully offline and
deterministically.

## Trust anchors

The `fixtures/` ground truth and the detector/scorer code are frozen by
`guard.sh` after human sign-off (SHA-256 baseline). A tampered fixture or scorer
is detected with its exact path and diff before any audit is trusted.
