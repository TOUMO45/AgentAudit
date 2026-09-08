"""Export the vulnerable-fixture scorecard as a single static page (item 2.9).

Produces a self-contained HTML file (no backend, no auth, no per-user state — it
does not accept input or run scans) suitable for GitHub Pages so judges can open
the demo without cloning. This stays firmly on the static-artifact side of the
charter's 'no hosted SaaS' anti-goal.

    python scripts/export_static_demo.py            # -> docs/demo/index.html
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
    ap.add_argument("--out", default="docs/demo/index.html")
    args = ap.parse_args()

    card = run_audit(args.agent)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    renderer.render_html(card, str(out))
    print(f"wrote static demo -> {out} (grade {card.grade}, {len(card.findings)} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
