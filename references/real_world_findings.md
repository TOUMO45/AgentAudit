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
