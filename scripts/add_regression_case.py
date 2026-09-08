"""Add a fixture to the regression corpus (Phase 2 item 2.4).

Given a fixture path and a short description, this copies the file into
``fixtures/regression/``, snapshots the detectors AgentAudit's static analyzer
currently raises on it (locking that behavior in), records a manifest entry, and
re-runs the suite so the new case is immediately enforced.

The regression test discovers cases from the manifest automatically, so a new
case increases the test count with **no edits to any test file**.

Usage:
    python scripts/add_regression_case.py --fixture path/to/agent.py \
        --desc "why this case matters" [--name reg_short_name] [--no-test]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.layers import static_graph  # noqa: E402

CORPUS = Path("fixtures/regression")
MANIFEST = CORPUS / "manifest.json"


def _load() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {"cases": []}


def add_case(fixture: str, desc: str, name: str | None = None) -> dict:
    src = Path(fixture)
    if not src.exists():
        raise SystemExit(f"fixture not found: {fixture}")
    CORPUS.mkdir(parents=True, exist_ok=True)

    stem = name or f"reg_{src.stem}"
    dest = CORPUS / f"{stem}.py"
    shutil.copyfile(src, dest)

    detectors = sorted({f.detector for f in static_graph.analyze(str(dest))})
    manifest = _load()
    manifest["cases"] = [c for c in manifest["cases"] if c["file"] != dest.name]
    entry = {"file": dest.name, "description": desc, "expected_detectors": detectors}
    manifest["cases"].append(entry)
    manifest["cases"].sort(key=lambda c: c["file"])
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return entry


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--desc", required=True)
    ap.add_argument("--name")
    ap.add_argument("--no-test", action="store_true")
    args = ap.parse_args()

    entry = add_case(args.fixture, args.desc, args.name)
    print(f"Added regression case '{entry['file']}' -> {entry['expected_detectors']}")

    if not args.no_test:
        print("Re-running the suite to lock it in...")
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_regression_corpus.py"])
        return r.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
