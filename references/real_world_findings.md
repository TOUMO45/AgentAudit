# Real-World Verification (Phase 2 item 2.6)

AgentAudit's static analyzer was run against **independent, permissively-licensed
open-source Strands code we did not write** — not our own fixtures. Every finding
below was hand-verified by reading the actual source at the flagged line (the
charter's Gate 5: a human reads the real code, not the tool's summary).

## Targets

| Source | Repo | License | What it is |
|--------|------|---------|-----------|
| `strands-agents/samples` | https://github.com/strands-agents/samples | Apache-2.0 | Official example agents |
| `strands-agents-tools` (`strands_tools`) | https://github.com/strands-agents/tools | Apache-2.0 | Official library of agent tools (installed v0.8.8) |

Scope respected: both repos are public and Apache-2.0 (guardrail 2.6). No code
was modified; third-party source is not vendored into this repo — findings cite
`file:line` and short excerpts only.

## Hand-verified findings

### 1. `samples/.../step-01-tools/tools/calculator.py:6` — confused-deputy — **TRUE POSITIVE**
The `calculator` tool passes the untrusted `expression` parameter into
`eval(expression, {"__builtins__": {}}, {})`. The author attempted a sandbox by
emptying `__builtins__`, but that construct is well-known to be escapable (e.g.
via `().__class__.__bases__[0].__subclasses__()`). AgentAudit correctly does not
treat an empty-builtins dict as validation. **Verdict: real, useful finding** —
`eval` of model-controlled input is dangerous even with the attempted guard.

### 2. `strands_tools/{agent_core_memory,memory,mongodb_memory,workflow}.py` — confused-deputy — **TRUE PATTERN, by-design**
Four tools forward an unvalidated resource id (`memory_record_id`,
`document_id`, `memory_id`, `workflow_id`) into a delete sink
(`delete_memory_record`, `delete_document`, `_delete_memory`, `delete_workflow`).
These are genuine matches of the pattern: a caller-supplied id drives a
privileged delete with no ownership/authorization check in the tool body. For a
**general-purpose tool library** this is expected — authorization is meant to be
enforced by the deploying application. This is exactly what AgentAudit is for:
surfacing the boundary so the app owner confirms authz exists upstream. **Verdict:
correct to surface; not a library bug, but a real prompt for the integrator.**

### 3. `strands_tools/graph.py:405` — confused-deputy — **TRUE PATTERN, by-design**
`graph_id` flows into `execute_graph(...)` (and a `del self.graphs[graph_id]`
delete path). Same character as #2.

## False positive found — and fixed

### `strands_tools/shell.py:432` — confused-deputy on `ignore_errors` — **FALSE POSITIVE (fixed)**
Original finding flagged `ignore_errors` flowing into `execute_commands(...)`.
`ignore_errors` is a **boolean flag** (`ignore_errors: bool = False`), not a
command payload — it cannot carry an injection.

**Root cause:** the confused-deputy detector tainted *every* non-context
parameter equally and reported the first one appearing in the sink call; the sink
`execute_commands` matched the `execute` fragment, and the boolean flag happened
to be a direct argument.

**Fix (`_nonpayload_params` in `agentaudit/layers/static_graph.py`):** parameters
that are `bool`/`int`/`float`-typed or bool/int-defaulted are excluded from the
confused-deputy taint set — they cannot carry a payload. This is precise and
low-risk; all fixtures and the mutation suite stay green.

**Post-fix behavior:** shell.py now flags `work_dir` (a `str` that flows into
command execution) instead. For a tool whose explicit purpose is running shell
commands this is a defensible true positive — though `command` is the primary
vector, and the detector attributes to the directly-passed string parameter. We
accept this as a genuine (if imprecisely attributed) surfacing rather than
suppress a shell-execution tool.

## Honest limitation noted (false negative, deferred)

`samples/.../get_booking_details.py` reads a DynamoDB row by a
conversation-supplied `booking_id` with no ownership check — arguably a real
IDOR — but AgentAudit did **not** flag it, because the IDOR detector recognizes
global-dict/known-lookup-store access, not boto3 resource handles
(`table.get_item(Key=...)`). Extending IDOR to boto3/DB client handles needs its
own positive/hardened fixtures and a fresh false-positive analysis, so it is
**explicitly deferred** to a future item rather than bolted on here.

## Verifier status
- ≥1 finding hand-verified against real source: **yes** (calculator.py, verified true positive).
- False positive found, root-caused, and fixed: **yes** (shell.py `ignore_errors`).
- False negative surfaced and explicitly deferred with reasoning: **yes** (boto3 IDOR).

---

# Step 4 — Multi-repo real-world validation (2026-09-10)

Ran **Layer 2 only** (static trust-graph + capability-graph AST analysis) against
public GitHub repos using `strands-agents`. No AWS. No execution of any cloned
code. No PRs/issues opened.

**Running count:** 9 repos cloned (a 10th, `PacktPublishing/AI-Agents-on-AWS`,
timed out on clone and was skipped) · ~30 Strands agent files statically scanned
· 12 raw findings · **2 repos with a clear permissive license** contributed to
this log.

> **License gate (project guardrail):** findings are only logged below for repos
> with an explicit MIT/Apache/BSD license. Repos scanned but **excluded from
> this log for lacking an explicit license**: `ai-agents-frameworks`,
> `Sandbox-on-EC2`, `costco-price-match`, `strands-agents-workshop`,
> `sample-agentic-ai-factory`. (Several of the excluded repos did produce
> plausible `eval`/`subprocess` confused-deputy hits on inspection, but their
> code is not reproduced or catalogued here.)

## Verified true positives

### 1. `kyopark2014/strands-agent` — `application/strands_agent.py:195` — confused-deputy — **TRUE POSITIVE**
Repo license: **Apache-2.0**. Commit `74af997c3c626fb6ff69359e239c8dde34301c97`.
Link: https://github.com/kyopark2014/strands-agent/blob/74af997/application/strands_agent.py#L195

`@tool execute_code(code: str)` runs `exec(code, _exec_globals)` on the raw
conversation string. `_exec_globals` is defined with `"__builtins__":
__builtins__` (the **full** builtins) plus `subprocess`, `os`, `sys`, `shutil`,
`requests`. There is no sandbox, allowlist, or AST check. This is unrestricted
remote code execution driven by model output. The detector's CRITICAL
confused-deputy verdict is correct.

### 2. `kyopark2014/strands-agent` — `application/strands_agent.py:545` — confused-deputy — **TRUE POSITIVE**
Link: https://github.com/kyopark2014/strands-agent/blob/74af997/application/strands_agent.py#L545

`@tool bash(command: str)` runs `subprocess.run(command, shell=True, cwd=WORKING_DIR,
env=os.environ, timeout=300)` on the raw conversation string. Same class as the
`execute_code` finding — raw shell from model-controlled input, no validation.
CRITICAL confused-deputy is correct.

### 3. `kyopark2014/strands-agent` — `application/strands_agent.py:278` — exfiltration-capability-pair (write+network) — **TRUE POSITIVE**
Link: https://github.com/kyopark2014/strands-agent/blob/74af997/application/strands_agent.py#L278

`@tool upload_file_to_s3(filepath: str)` reads a local file and uploads it to S3,
returning a public download URL. In the same agent, `execute_code` and `bash`
can write arbitrary files. Chain: exec/bash writes `~/.aws/credentials` or an
env-secret dump to `artifacts/x`, then `upload_file_to_s3("artifacts/x")`
returns a public URL — a complete, in-session data-exfiltration path. This is
exactly the capability pair the detector is built to surface. HIGH is correct.
(Minor: the detector attributes both legs to `upload_file_to_s3` because that
one tool is classified WRITE+READ_DATA+NETWORK on its own; the staging leg is
really `execute_code`/`bash`. The finding itself — "this tool set has a
write→network exfil path" — is right.)

## Borderline / lower-confidence

### 4. `kyopark2014/strands-agent` — `strands_agent.py:429` — exfiltration-capability-pair (read+network) — **WEAK TRUE POSITIVE**
`get_skill_instructions` (reads a fixed plugin/skill directory) + `upload_file_to_s3`
(network egress) trips the read+network MEDIUM rule. The read tool only touches
a fixed skills path, not arbitrary data, so the practical exfil value is low —
but a read+egress pair in one agent is a fair thing to flag at MEDIUM.

## New detector-precision gap (partial false positive) — DEFERRED

### 5. `strands-rl/strands-sglang` — `calculator` (×3) — confused-deputy fires, but `eval` is guarded — **PARTIAL FALSE POSITIVE**
Repo license: **Apache-2.0**. Commit `a8f20c3987bce5f104f1726cc6b3e5b06a1f2e4f`.
Files: `examples/math_agent.py:19`, `examples/retokenization_drift/main.py:14`,
`tests/integration/conftest.py:137` (same copy-pasted function).

```python
allowed = set("0123456789.+-*/() ")
if not expression or set(expression) - allowed:
    return f"Unsupported expression: {expression!r}"
return str(eval(expression, {"__builtins__": {}}, {}))
```

The detector reports CRITICAL confused-deputy (`expression` → `eval`, no
recognized validation). But there **is** a guard: a character allowlist via
`set(expression) - allowed`. With no letters, underscores, brackets, or quotes
possible, the classic `().__class__.__bases__...` sandbox escape is blocked —
this is **not** RCE like finding #1.

**Root cause:** the confused-deputy detector's validation recognition
(`_VALIDATION_CALLS`) matches *named* calls like `validate(x)` / `sanitize(x)`.
It does not recognize a set-difference character-allowlist guard
(`set(param) - allowed_set` followed by an early return/raise).

**Residual risk (why it is not a *pure* FP):** `eval` on model-influenced input
is still fragile — widening `allowed` in a later refactor silently reintroduces
RCE — and giant-number arithmetic (`eval("9"*300 + "**" + "9"*80)`) is a
CPU/DoS vector the allowlist does not stop.

**Decision: DEFER the fix.** Recognizing char-allowlist guards means touching
`static_graph.py` (the decisive-gate detector) three days before the deadline;
same conservative call as the earlier boto3-IDOR false negative. Tracked for
post-submission: add a `set(<param>) - <set-literal>`-then-guard pattern to the
confused-deputy validator, and downgrade "eval behind a strict allowlist" from
CRITICAL to LOW/informational rather than suppressing it.

## Step 4 verifier status
- ≥1 new true positive hand-verified against real source: **yes** — findings
  #1–#3 in `kyopark2014/strands-agent` (Apache-2.0), each with file/line/commit.
- New false-positive class found and root-caused: **yes** — finding #5
  (char-allowlist-before-eval not recognized), fix deferred with reasoning.
- Time box: ~50 min of the 2 h budget; stopped here with the permissively-
  licensed evidence catalogued.

---

# Step 4 (cont.) — curated targets via `cagataycali/awesome-strands-agents` (2026-09-10)

Ran the **live remote-scan feature** (`scan_remote_repo` — the exact code path
behind `POST /api/scan-remote`, with its URL-validation / size-cap / shallow-clone
/ 60s-clone-30s-scan / isolated-temp-dir / single-flight guardrails) against 5
repositories found through the maintained community index
[`cagataycali/awesome-strands-agents`](https://github.com/cagataycali/awesome-strands-agents).
No AWS. No execution of any cloned code — `ast` parsing only. No PRs/issues opened.
Every scan left **0 residual temp directories**.

License is read from the GitHub repo API during the size precheck and recorded
below; findings are only catalogued for repos with an explicit MIT/Apache/BSD
license (project guardrail 2.6).

| # | Repo | License | Strands `@tool` files / .py scanned | Findings |
|---|------|---------|-----------|----------|
| 1 | [`cagataycali/strands-fun-tools`](https://github.com/cagataycali/strands-fun-tools) | Apache-2.0 | 17 / 22 | **1 CRITICAL** (below) |
| 2 | `Anya2089/Airline-booking-demo-strandsagent-agentcore-ver2.0-withsolutionmanager` | none | 0 / — | `no_strands_code` (see note) |
| 3 | [`NithiN-1808/strands-sql`](https://github.com/NithiN-1808/strands-sql) | Apache-2.0 | 0 / — | `no_strands_code` (see note) |
| 4 | [`strands-agents/agent-builder`](https://github.com/strands-agents/agent-builder) (official) | Apache-2.0 | 3 / 36 | **0 — confirmed clean** |
| 5 | [`eraykeskinmac/strands-hubspot`](https://github.com/eraykeskinmac/strands-hubspot) | MIT | 1 / 6 | **0 — confirmed clean** |

## Verified true positive

### 6. `cagataycali/strands-fun-tools` — `strands_fun_tools/face_recognition.py` — confused-deputy — **TRUE PATTERN, by-design**
Repo license: **Apache-2.0**. Commit `741c090f952ea6e74c53270aa3bc97bd79637394`.
Link: https://github.com/cagataycali/strands-fun-tools/blob/741c090/strands_fun_tools/face_recognition.py

`@tool def face_recognition(action, collection_id=None, ..., face_id=None, ...)`
(decorator at **line 12**). Under `action == "delete_face"` the tool runs, at
**line 177**:

```python
if not collection_id or not face_id:
    return {"status": "error", "content": [{"text": "❌ collection_id and face_id required"}]}
rekognition.delete_faces(CollectionId=collection_id, FaceIds=[face_id])
```

The untrusted, model-controllable `collection_id` parameter flows into
`rekognition.delete_faces(...)` (a `delete` sink) with only a **presence check**
(`if not collection_id ...`), which is not validation or an allowlist. Same
character as the `kyopark2014/strands-agent` findings #2/#3 above: for a
**general-purpose community tool library**, per-caller authorization is expected
to be enforced by the deploying application, and surfacing that boundary is
exactly what AgentAudit is for. CRITICAL is defensible for a `delete` sink driven
by model-controlled input. **Verdict: correct to surface; a prompt for the
integrator, not necessarily a library bug.**

## Expected-clean controls — no over-firing

* **`strands-agents/agent-builder`** (official, Apache-2.0) — 3 Strands `@tool`
  files, **0 findings**, GRADE A. The detector does not over-fire on
  well-maintained first-party code.
* **`eraykeskinmac/strands-hubspot`** (MIT) — read-only-by-design HubSpot tool,
  1 Strands `@tool` file, **0 findings**, GRADE A. Confirms a genuinely
  read-only tool set produces nothing.

## Notes on the two `no_strands_code` results (both correct, one is a coverage gap)

* **#2 Airline-booking-demo** — no `.py` file contains both `from strands import`
  / `import strands` **and** `@tool`; the agent's tools are served through an
  **AgentCore MCP gateway** (`mcp-tools-server/mcp_server.py`), not `@tool`
  functions in the repo. Outside Layer 2's `@tool` scope. Also unlicensed, so it
  would not be catalogued regardless. Commit `cdd7224`.
* **#3 strands-sql** (Apache-2.0, commit `70021e1`) — the SQL tool is defined the
  **legacy way**: `def sql_database(tool: ToolUse, **kwargs) -> ToolResult`
  (`src/strands_sql/sql_database.py:569`) plus `strands.tools.Tool` wrappers —
  **no `@tool` decorator anywhere**. `static_graph.discover_tools` only finds
  `@tool` / `@tool(...)` definitions (charter scope), so the repo is correctly
  reported as having no analyzable Strands agent code. **Coverage gap noted:**
  the pre-`@tool` `(tool: ToolUse, **kwargs) -> ToolResult` tool form is not yet
  parsed — same "explicitly deferred" treatment as the boto3-IDOR and
  char-allowlist-eval gaps above.

## Step 4 (cont.) verifier status
- New true positive hand-verified against real source: **yes** — finding #6 in
  `cagataycali/strands-fun-tools` (Apache-2.0), file + line + commit.
- Two expected-clean controls confirmed clean (0 findings): **yes** —
  `agent-builder`, `strands-hubspot`.
- Detector coverage gap surfaced and deferred with reasoning: **yes** — legacy
  `ToolUse`/`ToolResult` tool form (`strands-sql`).
- Time box: ~35 min of the 90 min budget; all 5 scans completed, temp dirs clean.
