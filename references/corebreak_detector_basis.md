# CoreBreak detector — basis (CVE-2026-18830)

Evidence for the `harness-model-skip-corebreak` detector
(`agentaudit/layers/harness_integrity.py`). Same evidentiary bar as
`references/real_world_findings.md`: every non-obvious claim is a pasted real
excerpt with file+line, or a cited authoritative source that was actually read.

## 1. Installed / pinned SDK version

```
$ .venv/Scripts/python -m pip show strands-agents
Name: strands-agents
Version: 1.55.0
```
`requirements.txt`: `strands-agents==1.55.0`. Per <https://strandsagents.com/changelog/>
(read 2026-09-10), **1.55.0 (2026-09-08) is the latest release**.

## 2. The vulnerable path is present — verbatim from the installed source

`​.venv/Lib/site-packages/strands/event_loop/event_loop.py` (v1.55.0):

```python
105  def _has_tool_use_in_latest_message(messages: "Messages") -> bool:
106      """Check if the latest message contains any ToolUse content blocks.
...
114      if len(messages) > 0:
115          latest_message = messages[-1]
116          content_blocks = latest_message.get("content", [])
117
118          for content_block in content_blocks:
119              if "toolUse" in content_block:
120                  return True
121      return False
```

```python
289          # Resume a tool interrupt by replaying its stored message instead of calling the model.
290          pending_tool_execution = agent._interrupt_state.pending_tool_execution
291          if agent._interrupt_state.activated and pending_tool_execution is not None:
292              ...
293          # Skip model invocation if the latest message contains ToolUse
294          elif _has_tool_use_in_latest_message(agent.messages):
295              stop_reason = "tool_use"
296              message = agent.messages[-1]
297          else:
298              model_events = _handle_model_execution(...)   # <-- the model call that is skipped
```

Any `toolUse` block in `agent.messages[-1]` makes the loop set
`stop_reason = "tool_use"` and proceed straight to tool execution with that
block's `input`, skipping `_handle_model_execution` (line 299) and every
model-time guardrail.

## 3. CVE / disclosure / upstream patch status

| | |
|---|---|
| CVE | **CVE-2026-18830** ("CoreBreak"), CVSS v4.0 **8.6**, **CWE-1287** (improper input validation) |
| Disclosed | Black Hat 2026 (~2026-08-31); researchers Aviyam Ivgi & Hedi Ingber |
| AWS bulletin | [2026-073](https://aws.amazon.com/security/security-bulletins/2026-073-aws/) (2026-08-04) — server-side input validation added to the **managed** AgentCore `InvokeHarness` API ("mitigation is applied automatically") |
| Open-source SDK | **Not patched.** "AWS fixed the managed AgentCore service but declined a code change for the open-source Strands Python SDK" — [Redpanda](https://www.redpanda.com/blog/corebreak-ai-agent-vulnerability); corroborated by [The Hacker News](https://thehackernews.com/2026/08/aws-google-and-vercel-patch-agent-flaws.html), [TechTimes](https://www.techtimes.com/articles/323397/20260806/aws-fixed-its-managed-agent-service-left-strands-python-sdk-unpatched.htm), [CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-agent-infra-guardrail-bypass-20260806-csa/). An April 2026 PR to remove the shortcut "was closed without merging" (Redpanda). The `strands-agents` changelog through 1.55.0 has no entry for this path. |

## 4. Why the detector checks the *user's* code, not the SDK

* A **version-pin check cannot say "patched"** — every released `strands-agents`,
  including the newest 1.55.0, still contains the path.
* An **AST check of the installed `site-packages`** is pointless — the pattern is
  in every version and the user cannot fix it there.
* The one thing the deployer controls is whether **caller-supplied conversation
  history reaches the Agent with attacker-suppliable `toolUse` / `tool_use`
  content blocks still in it.** That is what `harness-model-skip-corebreak`
  checks (option **(c)** from the approved research).

### FAIL condition (CRITICAL)

`analyze()` emits the finding only when **all** hold:

1. a function parameter / dict key that carries caller history
   (`messages`, `history`, `conversation`, `event["messages"]`, …) is bound to a
   local — `harness_integrity._history_sources`;
2. that value flows into `Agent(messages=…)`, `agent.messages = …`,
   `agent.messages.extend/append(…)`, or `agent.invoke/stream_async/run(…)` —
   `harness_integrity._reaches_agent`;
3. **no** mitigation is present — `harness_integrity._has_mitigation`:
   * a call/def named like `strip_tool_use` / `sanitize_messages` /
     `filter_history` (`_SANITIZE_RE`), **or**
   * a comprehension / membership test / `.get()` / `.pop()` on the literal
     `"toolUse"` or `"tool_use"`, **or**
   * a `BeforeModelCall` / `before_model_call` hook (`_HOOK_RE`), **or**
   * an **explicit deployer attestation** in `<agent>.deploy.json` (see below).

A single-prompt agent that never ingests structured caller history is **not**
flagged — CoreBreak requires the attacker to place a `toolUse` block into
`messages[-1]`, which needs the app to accept structured message input.

### The "managed-InvokeHarness" clause — a *deployment* fact, attested, not detected

Whether an agent is invoked **only** through the patched managed AgentCore
`InvokeHarness` API (which AWS *did* fix) is a property of *how it is deployed*,
not of the source file — it **cannot be read from local code**. The detector
therefore honours it only when the deployer declares it in the same
`<agent>.deploy.json` descriptor the cloud-posture layer already reads, via
exactly one of:

```json
{ "corebreak_mitigation": true }
```
```json
{ "invocation": "agentcore-managed-invoke-harness" }
```

`_has_mitigation` clause 3 checks `cfg.get("corebreak_mitigation") is True` or
`cfg.get("invocation") == "agentcore-managed-invoke-harness"` — nothing fuzzier.
Any other value (including a truthy string like `"yes"`) does **not** clear the
flag. `fixtures/corebreak_managed_invoke.py` exercises this branch.

### CLEAN wording (never "detects CoreBreak")

> "strands-agents is affected by CVE-2026-18830 (CoreBreak) and has no upstream
> fix; verified your agent strips caller-suppliable tool_use blocks from incoming
> message history before the harness — **or its deploy descriptor attests** it
> runs only via the patched managed InvokeHarness API."

## 5. Fixtures

| Fixture | Expected |
|---|---|
| `fixtures/corebreak_vulnerable.py` | `handle_request` passes `event["messages"]` straight into `Agent(messages=…)` → **1 finding, `harness-model-skip-corebreak` CRITICAL** at the `Agent(...)` line |
| `fixtures/corebreak_hardened.py` | same shape, but `_strip_tool_use(event["messages"])` first → **0 findings** |
| `fixtures/corebreak_managed_invoke.py` (+ `.deploy.json`) | **identical unsanitized handler** to the vulnerable fixture, but `corebreak_managed_invoke.deploy.json` sets `"corebreak_mitigation": true` → **0 findings** (attestation clears the flag; proves clause 3 works and is not a source check) |

## 6. Scope

Detection only. This repo contains **no** PoC, no crafted malicious message, and
sends nothing to any live agent. The check is `ast`-parse only — it never
imports or executes the target (a test asserts a module that `raise`s on import
is still analysed).

## 7. ASI mapping

`harness-model-skip-corebreak → [ASI01, ASI05]` (see
`references/asi_2026_mapping.md` and `agentaudit/taxonomy/asi_2026.py`).
