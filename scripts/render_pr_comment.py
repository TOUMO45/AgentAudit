"""Render a signed scorecard as a Markdown table for a PR comment (item 2.8).

    python scripts/render_pr_comment.py --json out/vuln/report.signed.json > comment.md

The CI job feeds the resulting Markdown to actions/github-script, which posts
(or updates) a single comment on the pull request.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def render(data: dict) -> str:
    grade = data.get("grade", "?")
    score = data.get("score", 0)
    counts = data.get("counts_by_severity", {})
    findings = data.get("findings", [])
    agent = data.get("agent_path", "?")

    head = (
        f"### 🛡️ AgentAudit — grade **{grade}** · risk {score}/100\n"
        f"`{agent}` · "
        + " · ".join(f"{EMOJI[s]} {counts.get(s,0)} {s}" for s in ('critical','high','medium','low'))
        + "\n\n"
    )
    if not findings:
        return head + "✅ No findings. This agent passed every enabled check.\n"

    rows = ["| Sev | Layer | Detector | Location | Finding |",
            "|-----|-------|----------|----------|---------|"]
    for f in findings:
        sev = f.get("severity", "")
        rows.append(
            f"| {EMOJI.get(sev,'')} {sev} | {f.get('layer','')} | `{f.get('detector','')}` "
            f"| `{f.get('location','')}` | {f.get('title','')} |"
        )
    sig = data.get("signature", {})
    foot = f"\n<sub>signed {sig.get('alg','')} · {str(sig.get('digest',''))[:22]}…</sub>\n"
    return head + "\n".join(rows) + "\n" + foot


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True)
    args = ap.parse_args()
    data = json.loads(Path(args.json).read_text(encoding="utf-8"))
    print(render(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
