"""Build the full judge-facing static site for GitHub Pages.

    python scripts/build_pages_site.py [--out _site]

Produces (all real output — no hand-typed numbers or mockups):

    _site/index.html                  landing page (docs/pages_src/index.template.html)
    _site/aibom.html                  a real AIBOM (docs/pages_src/aibom.template.html)
    _site/scorecard-vulnerable.html   agentaudit run --agent fixtures/vulnerable_agent.py
    _site/scorecard-hardened.html     agentaudit run --agent fixtures/hardened_agent.py
    _site/scorecard-corebreak.html    agentaudit run --agent fixtures/corebreak_vulnerable.py
    _site/agentaudit-badge.svg        copied from docs/

Every number the landing page shows (grades, rule counts, ASI-mapped counts,
test count, commit SHA, build time) is computed in this run against the real
code — this script never hard-codes a figure that could drift from reality.
"""

from __future__ import annotations

import argparse
import html
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentaudit.aibom import render_aibom  # noqa: E402
from agentaudit.audit import run_audit  # noqa: E402
from agentaudit.report import renderer  # noqa: E402
from agentaudit.taxonomy import asi_2026  # noqa: E402

SRC = ROOT / "docs" / "pages_src"

# grade -> ring colour, matching the dashboard's own palette (ui.html GRADE map)
GRADE_COLOR = {"A": "#5ee6a8", "B": "#8fe39a", "C": "#ffb020", "D": "#ff8a4c", "F": "#ff5470"}


def mini_ring(score: int, grade: str, size: int = 64) -> str:
    """A tiny inline SVG risk ring matching the dashboard's ring() component."""
    r = size / 2 - 8
    c = 2 * 3.14159265 * r
    off = c * (1 - score / 100)
    col = GRADE_COLOR.get(grade, "#9a9bb0")
    cx = cy = size / 2
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" class="ring">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="7"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" stroke-width="7" '
        f'stroke-linecap="round" stroke-dasharray="{c:.2f}" stroke-dashoffset="{off:.2f}" '
        f'transform="rotate(-90 {cx} {cy})"/>'
        f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" '
        f'class="g" fill="{col}">{html.escape(grade)}</text></svg>'
    )


_TERSE_LINE = re.compile(r"^tests[/\\][\w.]+\.py:\s*(\d+)\s*$")


def test_count_hint() -> str:
    """Live test count for the landing page copy. Handles both collection-output
    styles pytest may use (terse 'tests/x.py: N' per file, or one '::'-qualified
    line per test id) so it works regardless of how -q/addopts resolve in a
    subprocess. Never fails the build; falls back to a safe generic phrase."""
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--co"],
            cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        lines = r.stdout.splitlines()
        terse_total = sum(
            int(m.group(1)) for m in (_TERSE_LINE.match(ln.strip()) for ln in lines) if m
        )
        if terse_total:
            return f"{terse_total} tests"
        id_count = sum(1 for ln in lines if "::" in ln)
        if id_count:
            return f"{id_count} tests"
    except Exception:
        pass
    return "the full suite"


def git_short_sha() -> str:
    try:
        r = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5, check=False)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return "unknown"


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- real scorecards -----------------------------------------------------
    cards = {}
    for tag, agent in (
        ("vulnerable", "fixtures/vulnerable_agent.py"),
        ("hardened", "fixtures/hardened_agent.py"),
        ("corebreak", "fixtures/corebreak_vulnerable.py"),
    ):
        card = run_audit(agent)
        cards[tag] = card
        renderer.render_html(card, str(out_dir / f"scorecard-{tag}.html"))
        print(f"  scorecard-{tag}.html  -> grade {card.grade}  {len(card.findings)} finding(s)")

    # --- real AIBOM ------------------------------------------------------------
    aibom_json = render_aibom("fixtures/vulnerable_agent.py")
    aibom_tmpl = (SRC / "aibom.template.html").read_text(encoding="utf-8")
    (out_dir / "aibom.html").write_text(
        aibom_tmpl.replace("__AIBOM_JSON__", html.escape(aibom_json)), encoding="utf-8"
    )
    print("  aibom.html            -> real CycloneDX 1.6 BOM embedded")

    # --- landing page ------------------------------------------------------------
    rule_count = len(asi_2026.known_rule_ids())
    asi_mapped = len(asi_2026.RULE_ASI)
    tmpl = (SRC / "index.template.html").read_text(encoding="utf-8")
    subs = {
        "__RULE_COUNT__": str(rule_count),
        "__ASI_MAPPED__": str(asi_mapped),
        "__RING_VULN__": mini_ring(cards["vulnerable"].score, cards["vulnerable"].grade),
        "__RING_HARD__": mini_ring(cards["hardened"].score, cards["hardened"].grade),
        "__RING_COREBREAK__": mini_ring(cards["corebreak"].score, cards["corebreak"].grade),
        "__TEST_HINT__": test_count_hint(),
        "__BUILD_TIME__": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "__COMMIT_SHA__": git_short_sha(),
    }
    for token, value in subs.items():
        tmpl = tmpl.replace(token, value)
    (out_dir / "index.html").write_text(tmpl, encoding="utf-8")
    print(f"  index.html            -> {rule_count} rules, {asi_mapped} ASI-mapped, "
          f"commit {subs['__COMMIT_SHA__']}")

    # --- static assets ------------------------------------------------------------
    badge_src = ROOT / "docs" / "agentaudit-badge.svg"
    if badge_src.exists():
        (out_dir / "agentaudit-badge.svg").write_bytes(badge_src.read_bytes())
    diagram_src = SRC / "architecture-diagram.svg"
    if diagram_src.exists():
        (out_dir / "architecture-diagram.svg").write_bytes(diagram_src.read_bytes())

    # verify no leftover placeholders slipped through
    for name in ("index.html", "aibom.html"):
        text = (out_dir / name).read_text(encoding="utf-8")
        if "__" in text and any(tok in text for tok in ("__RULE_COUNT__", "__AIBOM_JSON__", "__BUILD_TIME__")):
            raise SystemExit(f"template placeholder left unsubstituted in {name}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="_site")
    args = ap.parse_args()
    build(Path(args.out))
    print(f"\nsite built -> {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
