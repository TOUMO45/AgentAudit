"""Export any one scorecard as a single static HTML page (item 2.9).

Produces a self-contained HTML file (no backend, no auth, no per-user state — it
does not accept input or run scans). This stays firmly on the static-artifact
side of the charter's 'no hosted SaaS' anti-goal.

The live GitHub Pages judge site is built by ``scripts/build_pages_site.py``
instead (a richer, multi-page site); this script remains for quick, one-off
local exports of a single agent's scorecard.

    python scripts/export_static_demo.py --agent fixtures/vulnerable_agent.py --out /tmp/scorecard.html
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.audit import run_audit  # noqa: E402
from agentaudit.report import renderer  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", default="fixtures/vulnerable_agent.py")
    ap.add_argument("--out", default="out/scorecard.html")
    args = ap.parse_args()

    card = run_audit(args.agent)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    renderer.render_html(card, str(out))
    print(f"wrote static demo -> {out} (grade {card.grade}, {len(card.findings)} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
