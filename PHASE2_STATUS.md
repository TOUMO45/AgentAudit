# Phase 2 — Status

Section 0 (mandatory pre-flight): **GREEN** — no signing key in history, key untracked
& env-var supported, guard OK, tests green, pushed to
https://github.com/TOUMO45/AgentAudit (branch `master`).

CI on GitHub Actions: **agentaudit-ci is GREEN** on a clean Linux/Python-3.11
checkout (integrity guard, CVD palette check, 81 tests, vulnerable-fails /
hardened-passes self-audits, badge regeneration).

| Item | Capability | Status | Verifier |
|------|-----------|--------|----------|
| 2.1 | Tool poisoning / rug-pull detection | ✅ DONE | day1→day2 = 1 finding; identical = 0 |
| 2.2 | Secrets-in-system-prompt (regex + entropy) | ✅ DONE | positive 1 finding; env-ref clean |
| 2.3 | SSRF-via-tool-param | ✅ DONE | positive flagged; allowlist clean |
| 2.4 | Self-discovering regression corpus | ✅ DONE | new case ⇒ test count ↑, no test edits |
| 2.5 | Mutation robustness | ✅ DONE | 3 variants × 5 patterns; pos flagged, hardened clean |
| 2.6 | Real-world verification | ✅ DONE | calculator.py TP hand-verified; shell.py FP fixed; FN deferred |
| 2.7 | Scorecard UI overhaul | ✅ DONE | CVD palette ΔE 25.4; SVG shield; collapsed cards; visual sent |
| 2.8 | CI PR-comment + grade badge | ✅ DONE | **PR #1: github-actions[bot] posted the findings table** (verified, then closed) |
| 2.9 | Static demo hosting (GitHub Pages) | ✅ DONE | live at https://toumo45.github.io/AgentAudit/ — byte-identical to local scorecard |

## CI-portability bugs found & fixed while going green (a red baseline is work item #1)
1. Integrity baseline was not portable: byte-hashed a CRLF working tree while
   `.gitattributes` checks out LF → guard now hashes CR-stripped content.
2. Baseline captured local `__pycache__/*.pyc` (absent on clean checkout) →
   guard now prunes them.
3. `pytest` console script (unlike `python -m pytest`) didn't add repo root to
   `sys.path` → added a root `conftest.py`.
4. `guard.sh` needed the git executable bit for `./guard.sh` on Linux.

## Loop-level verifier — all green
1. Full pytest suite green (incl. 2.1–2.5) — locally and on CI. ✅
2. `guard.sh check` → INTEGRITY OK. ✅
3. `references/real_world_findings.md` with ≥1 hand-verified real finding. ✅
4. Both scorecards render; delivered for the human visual check. ✅
5. Throwaway PR (#1) proved the CI comment posts real content (then closed). ✅
6. No signing key anywhere in git history. ✅

**Phase 2 complete.** GitHub Pages enabled with the user's explicit consent.
