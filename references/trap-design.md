# Trap Design — why a fixture can *pass*, not only fail

A security scanner that always finds something is worthless: it cannot tell a
safe agent from a dangerous one. AgentAudit's ground truth is built as a set of
**traps with matched escape hatches** so that every detector is proven to fire
on a real flaw *and* stay silent on the fixed version. This document records the
logic each detector keys on and, crucially, exactly what makes the hardened
negative control safe. If a detector ever disagrees with this file, the detector
is wrong (charter rule 1).

## The three-way proof

For each pattern we ship three artifacts:

1. **Positive** — the planted flaw. The detector *must* fire.
2. **Hardened control** — the same code with the flaw fixed. The detector *must*
   stay silent (zero false positives).
3. **Benign stub** (`empty_stub_agent.py`) — nothing to find at all, proving the
   scorer is not vacuously non-zero (charter success condition 3).

Only a detector that passes all three is trustworthy.

---

## IDOR-in-Agent (`idor-in-agent`, critical)

**Trap.** A subject/resource id (`account_id`, `document_id`, …) arrives as a
free tool parameter — i.e. it is controlled by the conversation, and therefore
by the user — and is used to read a **shared** data store, with no check that
the caller owns the record.

**Fires when all hold:**
- a parameter matches the subject/resource-id vocabulary, and it is *not* an
  injected `ToolContext`;
- that parameter indexes or is passed to a lookup on a store that is **not** a
  local literal defined inside the function (a module-level / global store, i.e.
  shared across callers);
- the function body contains **no** authorization call (`assert_owner`,
  `authorize`, `check_access`, …).

**Escape hatch (why hardened is safe).** The hardened tool resolves identity from
`ctx.session` (so no untrusted id parameter exists) *or* calls `assert_owner(...)`
before returning the record. Either one clears the flag. The hardened
`lookup_diagnostic` reads a **local literal** dict, which is not a shared store,
so it is not IDOR even though it takes a `case_id`.

## Confused Deputy (`confused-deputy`, critical)

**Trap.** A low-privilege tool forwards an untrusted parameter *directly* into a
privileged sink (shell exec, admin/ledger/transfer helper) with no validation in
between — the tool becomes a deputy the user can confuse.

**Fires when:** an untrusted parameter (or a plain alias of it) appears as a
direct argument to a call whose name is a privileged sink
(`os.system`, `subprocess.*`, `exec`/`eval`, or a name containing
`admin`/`grant`/`delete`/`credit_ledger`/`transfer`/…), and that value was never
passed through a validation/allowlist call.

**Escape hatch.** The hardened tool assigns `safe = validate_x(x)` (a call in the
validation vocabulary) and passes `safe` to the sink. Values derived from a
`ToolContext` are trusted identity, not untrusted input, so they never taint a
sink. Values embedded in an f-string are handled by the excessive-agency /
shell detector rather than double-reported here, keeping the mapping clean.

## Excessive Agency (`excessive-agency`, high)

**Trap.** A tool whose *declared* purpose is read-only (name starts with
`get`/`read`/`lookup`/… or the docstring says "read-only") performs a
**destructive** operation — shelling out, deleting files, writing/updating —
granting it authority far beyond what its purpose implies.

**Fires when:** a read-intent tool's body contains a dangerous call
(`os.system`, `os.remove`, `subprocess.*`, `shutil.rmtree`, `exec`/`eval`, or a
`.delete`/`.write`/`.update`/… method call).

**Escape hatch.** The hardened read tool only reads — it returns a lookup from a
constant or a store with no side effects — so its real capability matches its
declared purpose.

> This detector is `heuristic` confidence and is designed to admit an optional
> LLM tie-break for genuinely ambiguous cases (charter capability #4). The
> heuristic alone is sufficient for the ground-truth fixtures; the LLM is only a
> tie-breaker and is never required for a deterministic gate to pass (rule 2).

---

## Cloud posture traps

The `*.deploy.json` descriptors encode the same positive/hardened split at the
deployment layer:

| Detector | Positive (`vulnerable_agent.deploy.json`) | Hardened control |
|----------|-------------------------------------------|------------------|
| `iam-least-privilege` | `Action:"*"`, `Resource:"*"` | scoped bedrock/agentcore actions on explicit ARNs |
| `guardrails-attached` | `attached:false`, `guardrail_id:null` | `attached:true` with a real guardrail id |
| `memory-encryption-ttl` | `encryption_at_rest:false`, `ttl_days:null` | encryption on, TTL set |

The identical detector logic runs against **live** IAM policy documents fetched
read-only via boto3, so the offline fixture and the real cloud path share one
code path (`policy_findings`).
