# AgentAudit — Architecture

One CLI invocation (or one dashboard scan, local or remote) fans out to
independent detection layers, unifies every finding through a single model,
maps each to the OWASP Top 10 for Agentic Applications (2026), scores and
signs the result, and renders it four ways.

```mermaid
flowchart TD
    CLI["agentaudit run --agent &lt;file&gt;"] --> ORCH[Audit Orchestrator<br/><code>agentaudit/audit.py</code>]
    DASH["agentaudit dashboard<br/>(stdlib http.server)"] -.local scan.-> ORCH
    DASH -.."scan a public GitHub repo"..-> REMOTE

    subgraph ARCH["Layer 2 · Architectural — DECISIVE GATE (ast only, deterministic)"]
        SG["static_graph.py<br/>IDOR-in-Agent · Confused Deputy · Excessive Agency<br/>SSRF-via-tool-param · secret-in-prompt"]
        CG["capability_graph.py<br/>exfiltration-capability-pair<br/>(WRITE/READ_SECRET/READ_DATA + NETWORK)"]
        SC["supply_chain.py<br/>tool-rug-pull (tool_spec drift)"]
        HI["harness_integrity.py<br/>harness-model-skip-corebreak<br/>(CVE-2026-18830)"]
    end

    ORCH --> ARCH
    ORCH --> L1["Layer 1 · Behavioral<br/>prompt hygiene + strands_evals.redteam wrapper"]
    ORCH --> L3["Layer 3 · Cloud Posture (read-only boto3)<br/>iam-least-privilege · guardrails-attached<br/>memory-encryption-ttl · runtime-network-mode · runtime-imdsv2"]

    ARCH --> SCORE
    L1 --> SCORE
    L3 --> SCORE

    SCORE["Unified Risk Scorer<br/>dedup by fingerprint · weight · grade A-F"] --> ASI["OWASP ASI 2026 taxonomy<br/><code>taxonomy/asi_2026.py</code><br/>12/14 rule_ids mapped, 2 explicit unmapped"]
    ASI --> SIGN[HMAC-SHA256 Signer]

    SIGN --> R1["HTML Scorecard<br/>+ ASI chip per finding"]
    SIGN --> R2["SARIF 2.1.0<br/>native OWASP-ASI-2026 taxonomy<br/>+ relevant relationships"]
    SIGN --> R3["Signed JSON<br/>CI gate · exit code"]
    SIGN --> R4["AIBOM<br/>CycloneDX 1.6<br/>tools+capabilities, model, deps, MCP, cap-pairs"]

    subgraph REMOTE["Remote GitHub scan (agentaudit/dashboard/remote_scan.py)"]
        VAL["validate URL<br/>(github.com only, no SSRF shapes)"] --> SIZE["GitHub API size + license precheck"]
        SIZE --> CLONE["git clone --depth 1<br/>isolated temp dir · single-flight lock<br/>60s clone / 30s scan budget"]
        CLONE --> RSCAN["SG + CG + HI<br/>(same 3 ast-only detectors — never imports the repo)"]
        RSCAN --> CLEAN["rmtree in finally<br/>(always, even on crash/timeout)"]
    end
    RSCAN -.reuses.-> ARCH
```

## Data flow

1. **Orchestrator** (`agentaudit/audit.py`) runs deterministic layers first
   (charter rule 2). Each layer returns a `LayerReport` with an explicit
   `ran` / `skipped` / `error` status so a skipped layer is never silently
   dropped from the verdict. The architectural layer itself now runs four
   sub-detectors in sequence — `static_graph`, `capability_graph`,
   `supply_chain` (imports the target — the *only* place that ever happens,
   and it's wrapped so a non-importable agent never crashes the audit), and
   `harness_integrity` (pure `ast`, never imports).
2. Every layer emits `Finding` objects sharing one vocabulary
   (`agentaudit/models.py`): detector id, layer, severity, evidence, and a
   diff-ready `Remediation`.
3. The **scorer** (`agentaudit/scorer.py`) deduplicates by fingerprint, sums
   severity weights into a 0–100 risk score, and assigns a letter grade —
   deterministically, so a CI gate is reproducible.
4. The **ASI 2026 taxonomy** (`agentaudit/taxonomy/asi_2026.py`) is the single
   source of truth mapping every `rule_id` to the OWASP Top 10 for Agentic
   Applications (2026). It is consulted by all three findings-facing
   renderers, never duplicated.
5. The **signer** (`agentaudit/signing.py`) HMACs a canonical serialization so
   the JSON report is tamper-evident.
6. The **renderers** (`agentaudit/report/`, `agentaudit/aibom.py`) emit four
   artifacts from the one scorecard: HTML, SARIF 2.1.0, signed JSON, and a
   CycloneDX 1.6 AI Bill of Materials.
7. The **dashboard** (`agentaudit/dashboard/`) is a stdlib-only HTTP server
   giving all of the above a live UI, for both **local fixture files** (runs
   the full 3-layer `audit.run_audit`) and **public GitHub repos** (runs only
   the pure-`ast` architectural detectors — `static_graph` +
   `capability_graph` + `harness_integrity` — against a shallow, isolated,
   single-flight, always-cleaned-up clone; behavioral and cloud posture are
   explicitly reported `skipped` for a source-only scan, never faked).

## Why the layers are independent

Each layer answers a different question and fails independently:

| Layer | Question | Determinism |
|-------|----------|-------------|
| Architectural | Do the tool trust boundaries hold — and is the harness itself sound? | deterministic (`ast`) |
| Behavioral | Does the model resist adversarial pressure? | heuristic + LLM |
| Cloud | Is the deployment posture least-privilege? | deterministic (`boto3`, read-only) |

The architectural layer is the **decisive gate**: it is the capability no
existing Strands/AgentCore tool provides, and it runs fully offline and
deterministically — including against **untrusted, remotely-fetched source**,
since it never executes anything it parses.

## The four architectural detector modules

| Module | Detects | Reads | Executes the target? |
|---|---|---|---|
| `static_graph.py` | IDOR-in-Agent, Confused Deputy, Excessive Agency, SSRF-via-tool-param, secret-in-prompt | `ast.parse` of one file | **Never** |
| `capability_graph.py` | exfiltration-capability-pair (dangerous tool-set combinations) | same AST, reused from `static_graph` | **Never** |
| `supply_chain.py` | tool-rug-pull (a trusted tool's spec silently changed) | imports the agent module to read `.tool_spec` | **Only local, user-owned files** — never a remote/fetched repo |
| `harness_integrity.py` | `harness-model-skip-corebreak` (CVE-2026-18830 / CoreBreak) | `ast.parse` + the agent's own `<agent>.deploy.json` | **Never** |

`agentaudit/dashboard/remote_scan.py` calls only the three ast-only modules
against a cloned repo — `supply_chain` (which imports) is deliberately
excluded from that path.

## AWS services this project uses or targets

| Service / API | Used for |
|---|---|
| **Amazon Bedrock AgentCore Runtime** | The deployed test agent (`GetAgentRuntime`, `ListAgentRuntimes*`) — network mode, IMDSv2, workload-identity posture |
| **Amazon Bedrock AgentCore Identity** | Workload identity present on the live runtime; Consent Portal posture researched (Sept 2026 feature) for future work |
| **Amazon Bedrock AgentCore Gateway / Policy Engine** | Target of the generated Cedar policies (`agentaudit/remediation/cedar.py`) that auto-remediate an exfiltration-capability-pair finding |
| **Amazon Bedrock AgentCore Memory** | Encryption-at-rest / TTL posture check |
| **Amazon Bedrock Guardrails** | Attached-and-active posture check |
| **Amazon Bedrock (model invocation)** | `bedrock:InvokeModel*` least-privilege check on the execution role |
| **AWS IAM** | Least-privilege analysis of the agent's execution role (offline against a deploy descriptor, or live read-only `Get*`/`List*`) |
| **Amazon ECR** | Container image for the deployed AgentCore runtime (referenced in the live posture evidence) |
| **Amazon CloudWatch Logs** | Observability target for the (future-work) unified-tracing fix |
| **Strands Agents SDK / `strands_evals`** (AWS open source) | The framework under test, and the red-team engine Layer 1 wraps |

Every live AWS call the tool itself makes is `Get*`/`List*` — read-only,
never a mutating call (charter rule 5).

## Trust anchors

The `fixtures/` ground truth and every detector/scorer module are frozen by
`guard.sh` (SHA-256 baseline, 37 protected paths as of Phase 2). A tampered
fixture or detector is caught with its exact path and diff before any audit is
trusted. `agentaudit/dashboard/remote_scan.py`, `agentaudit/taxonomy/`, the
report renderers, and `agentaudit/aibom.py` are intentionally **not** in that
frozen set — they consume the frozen detectors but aren't themselves ground
truth.
