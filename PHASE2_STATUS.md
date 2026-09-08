# Phase 2 — Status

Section 0 (mandatory pre-flight): **GREEN**
- `git log --all --full-history -- .agentaudit/signing.key` → empty (no secret in history).
- `.gitignore` covers `.agentaudit/`; key untracked; signing supports `AGENTAUDIT_SIGNING_KEY`.
- `guard.sh check` → INTEGRITY OK; full pytest suite green.
- Pushed Phase-1-complete state to https://github.com/TOUMO45/AgentAudit.git (branch `master`).

| Item | Capability | Status |
|------|-----------|--------|
| 2.1 | Tool poisoning / rug-pull detection | in progress |
| 2.2 | Secrets-in-system-prompt check | pending |
| 2.3 | SSRF-via-tool-param check | pending |
| 2.4 | Regression corpus wiring | pending |
| 2.5 | Mutation robustness | pending |
| 2.6 | Real-world verification | pending |
| 2.7 | HTML scorecard UI overhaul | pending |
| 2.8 | CI polish (PR comment + badge) | pending |
| 2.9 | Static demo hosting (GitHub Pages) | pending |
