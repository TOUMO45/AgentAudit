"""Generate a static SVG grade badge from a signed scorecard (Phase 2 item 2.8).

Run by CI from the last signed JSON so the README badge is never hand-edited.

    python scripts/make_badge.py --json out/hard/report.signed.json --out docs/agentaudit-badge.svg
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

GRADE_COLOR = {"A": "#3FB98A", "B": "#8CC152", "C": "#D9b93b", "D": "#D9772A", "F": "#F0486B"}


def make_svg(grade: str, score: int) -> str:
    color = GRADE_COLOR.get(grade, "#8B97A7")
    label, value = "agentaudit", f"{grade}  ({score}/100 risk)"
    lw, vw = 74, 108
    w = lw + vw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: grade {grade}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <rect rx="3" width="{w}" height="20" fill="#161D2B"/>
  <rect rx="3" x="{lw}" width="{vw}" height="20" fill="{color}"/>
  <rect rx="3" width="{w}" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2}" y="14">{label}</text>
    <text x="{lw + vw/2}" y="14" fill="#0E1420" font-weight="bold">grade {value}</text>
  </g>
</svg>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True)
    ap.add_argument("--out", default="docs/agentaudit-badge.svg")
    args = ap.parse_args()

    data = json.loads(Path(args.json).read_text(encoding="utf-8"))
    svg = make_svg(data.get("grade", "?"), data.get("score", 0))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(svg, encoding="utf-8")
    print(f"wrote {out} (grade {data.get('grade')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
