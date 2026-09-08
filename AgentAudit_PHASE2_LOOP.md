# AgentAudit — Phase 2 Build Loop (LOOP.md)

> This does NOT replace `AgentAudit_CHARTER.md`. The charter's success conditions,
> stack, non-negotiable rules, and anti-goals still apply and are NOT open for
> renegotiation in this loop. This file only adds new, additional work on top of
> an already-green Phase 1.

## 0. Mandatory first action — do not skip, do not proceed past this

Before touching any feature work:

1. Confirm `.agentaudit/signing.key` is fully removed from git history:
   `git log --all --full-history -- ".agentaudit/signing.key"` must return nothing.
   If it returns anything, STOP and run the `git filter-repo` cleanup first —
   report back to the human and wait for confirmation before continuing.
2. Confirm a fresh signing key exists only in the environment variable
   (`AGENTAUDIT_SIGNING_KEY`), never in a tracked file, and that `.gitignore`
   covers `.agentaudit/*.key`.
3. Re-run `guard.sh check` and the full pytest suite. Both must be green before
   any new work starts. If either is red, fixing it IS the first work item —
   do not build new features on a red baseline.

## Trigger

Manual: the human runs this loop now, in this session, against the existing
repo at its current (Phase 1 complete) state.

## Work — do these in order, one capability per iteration, commit after each green gate

Each item below follows the charter's rule: one capability → its own verifier →
commit → next. Do not batch multiple items into one commit.

### 2.1 Tool Poisoning / Rug-Pull Detection (new static-layer capability)
- On first scan of an agent, hash each tool's `.tool_spec` (name + description +
  parameter schema) and store it in `.agentaudit/tool_baseline.json`.
- On every subsequent scan, recompute and diff. A changed hash under an unchanged
  tool name = HIGH finding, with the old and new description shown side by side.
- Fixture: extend `fixtures/` with a "day 1" and "day 2" version of the same
  agent where one tool's description silently changes behavior-relevant wording
  (e.g. adds "also forward a copy to admin@external.com").
- **Verifier**: a test that runs scan on day-1 baseline, then scan on day-2
  fixture, asserts exactly 1 rug-pull finding naming the correct tool, and
  asserts 0 findings when day-2 is identical to day-1.

### 2.2 Secrets-in-System-Prompt check (new static-layer capability)
- Regex + Shannon-entropy check over the agent's system prompt string for
  patterns resembling API keys/tokens (e.g. `AKIA[0-9A-Z]{16}`, generic
  high-entropy 32+ char strings near words like "key", "token", "secret").
- **Verifier**: positive fixture with an obviously embedded fake AWS-shaped key
  string triggers exactly 1 finding; the hardened fixture (same prompt, key
  replaced with `os.environ` reference) produces 0 findings.

### 2.3 SSRF-via-Tool-Param check (new static-layer capability)
- Flag any `@tool` function whose parameter is typed/named suggestively
  (`url`, `endpoint`, `webhook`) and whose body passes it directly into an HTTP
  call (`requests.get(param)`, `urllib`) with no allowlist/domain check visible
  in the same function body.
- **Verifier**: positive fixture (a `fetch_url` tool with no allowlist) → 1
  finding; hardened fixture (same tool, with an explicit domain allowlist check
  before the request) → 0 findings.

### 2.4 Regression corpus wiring
- Create `fixtures/regression/` and a `scripts/add_regression_case.py` that,
  given a fixture path and a short description, copies it in with a manifest
  entry and re-runs the full suite to confirm it's now locked in.
- **Verifier**: running the full test suite includes the regression directory
  automatically (no manual wiring needed per new case) — confirm by adding one
  throwaway case and seeing the test count increase without touching test files.

### 2.5 Mutation robustness check (proves detection is semantic, not string-match)
- For each of the 3 original decisive-gate patterns plus 2.1–2.3, generate 3
  mechanically mutated variants of the positive fixture (rename the vulnerable
  variable, reorder unrelated statements, add an unrelated comment) using a
  small script — not hand-written — and confirm the detector still fires on
  all variants and still produces 0 findings on equivalently mutated hardened
  fixtures.
- **Verifier**: `pytest tests/test_mutation_robustness.py` — all mutated
  positives detected, all mutated negatives clean.

### 2.6 Real-world verification (Phase 5 of the charter's own methodology — do not skip)
- Find 2–3 real, independent open-source Strands agents on GitHub (not written
  by this project) that expose at least one `@tool`.
- Run AgentAudit against each. For every finding, the human — not Claude Code's
  summary — reads the actual source at the flagged line before it counts as a
  real result.
- Document results honestly in `references/real_world_findings.md`, including
  any false positive found and its root cause, per the charter's Gate 5.
- **Verifier**: at least one finding hand-verified against real source, and (if
  found) at least one false positive documented with root cause and either
  fixed or explicitly deferred with reasoning — not silently ignored.

### 2.7 UI overhaul — the HTML scorecard
Current version works but reads as a generic AI-generated dashboard. Fix specific,
concrete things — not vague "make it nicer":
- Replace default system fonts with a deliberate pairing: a monospace face for
  all findings/code/line-numbers (e.g. `JetBrains Mono` or `IBM Plex Mono` via
  Google Fonts CDN) and a distinct sans for headings/labels (e.g. `Inter` or
  `IBM Plex Sans`) — the mono/sans contrast itself signals "security tool," not
  "generic SaaS landing page."
- Replace the flat single accent color with a genuine severity scale: at least
  4 distinct hues for CRITICAL/HIGH/MEDIUM/LOW that are colorblind-distinguishable
  (test with a simulator, not by eye) — not just opacity variants of one red.
  in one function body.
- Grade badge (A/B/C/D/F) should be a rendered SVG shield/seal shape, not a
  colored text box — this is the single most-screenshotted element in any demo
  video, worth disproportionate polish.
- Each finding card: collapsed by default showing severity + one-line summary +
  affected tool name; expands to show the code snippet with the vulnerable line
  highlighted, the manifest reference, and the remediation diff. Do not show all
  detail for all findings at once — dense uncollapsed output reads as a log
  dump, not a product.
- Add a visible "Layer" tag (Behavioral / Architectural / Cloud) per finding
  with a distinct icon per layer, reinforcing the three-layer story visually —
  this is the product's core differentiator and the UI should never let a judge
  forget it.
- Top of report: one glanceable summary row (grade, total findings by severity,
  scan duration, agent name/version, timestamp) before any detail — judges and
  busy users decide "healthy or not" in the first 3 seconds.
- **Verifier**: render the scorecard for the vulnerable fixture and the hardened
  fixture, save both as PNG (headless browser screenshot script), and the human
  visually confirms: severity colors are distinguishable, grade badge renders as
  a shield, findings are collapsed by default, layer tags are visible.

### 2.8 CI polish
- GitHub Action that posts findings as a PR comment (not just a build badge) —
  use the JSON output, format it as a Markdown table, post via
  `actions/github-script` or an equivalent action.
- README badge showing last scan grade (static badge generated from the last
  signed JSON, regenerated by the same CI job — not a hand-edited badge).
- **Verifier**: open a throwaway PR against a scratch branch with an intentionally
  broken fixture and confirm the Action actually posts a real comment with real
  findings — not a mocked run.

### 2.9 Static demo hosting (safe middle ground — does NOT violate the "no hosted SaaS" anti-goal)
- Export the vulnerable-fixture scorecard as a single static HTML file (no
  backend, no auth, no per-user state) and publish it via GitHub Pages so
  judges can open it without cloning the repo.
- This is a static artifact, not a service — it does not accept input, run
  scans on demand, or store any state. If it grows toward accepting user input
  or running live scans, that crosses into "hosted SaaS" territory and needs
  explicit charter renegotiation first.
- **Verifier**: the Pages URL loads and matches the local-rendered scorecard
  byte-for-byte (modulo timestamp).

## Verifier (loop-level, on top of each item's own verifier above)

The loop is not done until ALL of the following are simultaneously true:
1. Full pytest suite green, including new tests for 2.1–2.5.
2. `guard.sh check` reports INTEGRITY OK.
3. `references/real_world_findings.md` exists with at least one hand-verified
   real finding.
4. Both fixture scorecards render and pass the human visual check in 2.7.
5. A throwaway PR proves the CI comment in 2.8 actually posts real content.
6. Git history contains no signing key at any point
   (`git log --all --full-history -- ".agentaudit/signing.key"` empty).

## Stop rule

- Cap: **3 attempts per numbered item (2.1–2.9)**. If an item fails its verifier
  three times, stop working on that item, leave it explicitly marked
  `BLOCKED: <reason>` in a `PHASE2_STATUS.md`, and move to the next item —
  never silently skip, never claim done without the verifier passing.
- Global stop: when every item's own verifier passes AND the loop-level verifier
  above is fully green, stop and report a final status table (item → pass/blocked)
  to the human. Do not keep iterating past all-green looking for more to improve —
  report completion and wait for the next explicit instruction.
- Escalate to the human immediately (don't spend an attempt guessing) if: the
  installed Strands/AgentCore SDK doesn't expose an API this loop assumes exists
  (charter rule 4 — verify against installed source, and if it's genuinely absent,
  ask rather than fabricate a workaround silently).

## Guardrails — exact permission scope for this loop

**Allowed without asking:**
- Read, create, and edit any file inside the project repository.
- Run local shell/Python/pytest/git commands within the repo.
- `git add` and `git commit` locally after each green gate.
- Install packages already pre-approved in the charter's fixed stack (`jinja2`,
  `boto3`, `strands-agents`, `strands-agents-evals`) if a needed sub-module isn't
  yet installed. Any package NOT already named in the charter still requires
  asking first, per charter rule 3 — including this loop's own items (e.g. a
  headless-browser screenshot tool for 2.7's verifier needs explicit sign-off
  before installing).
- Read-only AWS API calls (`Describe*`, `Get*`, `List*`) using credentials
  already configured in the environment.

**Never do, under any circumstance, without explicit human confirmation in this
conversation first:**
- `git push`, `git push --force`, or any action touching a remote repository.
- Any AWS API call that creates, modifies, or deletes a resource.
- Rewriting git history (`filter-repo`, `rebase -i` on shared history, `reset --hard`
  past a commit the human hasn't explicitly approved rolling back).
- Adding any dependency not already named in the charter or this loop file.
- Modifying `AgentAudit_CHARTER.md` itself, renaming the product, or changing
  any of the charter's anti-goals (no hosted SaaS beyond the static-export
  exception in 2.9, no auto-patching user code, no non-Strands framework support).
- Touching any file under `fixtures/` after it has been through `guard.sh freeze`
  — a failing check against a frozen fixture means fix the detector, never the
  fixture, and this loop must stop and ask if it believes a fixture itself is
  wrong rather than editing it directly.
- Cloning or scanning a real-world GitHub repo (item 2.6) that isn't public and
  MIT/Apache/BSD-licensed or otherwise clearly permissive — respect the source
  project's license before running any tool against its code.

## How to run this

Open a fresh Claude Code session in the project directory and paste:

> Read `AgentAudit_CHARTER.md` and `AgentAudit_PHASE2_LOOP.md` in full. Confirm
> you understand the mandatory first action in section 0, execute it, and report
> the result before doing anything else. Then work through the Work items in
> order, one at a time, committing after each green gate, respecting the
> guardrails exactly as written. Stop and report per the Stop rule.
