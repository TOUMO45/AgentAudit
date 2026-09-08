"""Phase 2 item 2.5: detection is semantic, not string-matching.

For each pattern, 3 mechanically mutated variants of the positive fixture must
still be flagged, and 3 mutated variants of the hardened control must stay clean.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import mutate  # noqa: E402

from agentaudit.layers import static_graph  # noqa: E402

# (label, positive_fixture, expected_detector, hardened_fixture)
PATTERNS = [
    ("idor", "fixtures/patterns/idor_positive.py", "idor-in-agent",
     "fixtures/patterns/idor_hardened.py"),
    ("confused_deputy", "fixtures/patterns/confused_deputy_positive.py", "confused-deputy",
     "fixtures/patterns/confused_deputy_hardened.py"),
    ("excessive_agency", "fixtures/patterns/excessive_agency_positive.py", "excessive-agency",
     "fixtures/patterns/excessive_agency_hardened.py"),
    ("secrets", "fixtures/patterns/secrets_positive.py", "secret-in-prompt",
     "fixtures/patterns/secrets_hardened.py"),
    ("ssrf", "fixtures/patterns/ssrf_positive.py", "ssrf-via-tool-param",
     "fixtures/patterns/ssrf_hardened.py"),
]

SEEDS = [1, 2, 3]


def _analyze_source(src: str, tmp_path: Path, name: str):
    p = tmp_path / f"{name}.py"
    p.write_text(src, encoding="utf-8")
    return {f.detector for f in static_graph.analyze(str(p))}


@pytest.mark.parametrize("label,positive,detector,hardened", PATTERNS, ids=[p[0] for p in PATTERNS])
@pytest.mark.parametrize("seed", SEEDS)
def test_positive_survives_mutation(label, positive, detector, hardened, seed, tmp_path):
    variant = mutate.mutate(Path(positive).read_text(encoding="utf-8"), seed)
    dets = _analyze_source(variant, tmp_path, f"{label}_pos_{seed}")
    assert detector in dets, f"{label} variant {seed} lost detection: {dets}"


@pytest.mark.parametrize("label,positive,detector,hardened", PATTERNS, ids=[p[0] for p in PATTERNS])
@pytest.mark.parametrize("seed", SEEDS)
def test_hardened_stays_clean_under_mutation(label, positive, detector, hardened, seed, tmp_path):
    variant = mutate.mutate(Path(hardened).read_text(encoding="utf-8"), seed)
    dets = _analyze_source(variant, tmp_path, f"{label}_hard_{seed}")
    assert detector not in dets, f"{label} hardened variant {seed} false-positived: {dets}"


def test_variants_are_distinct_and_parse():
    src = Path("fixtures/patterns/idor_positive.py").read_text(encoding="utf-8")
    vs = mutate.variants(src, 3)
    assert len({*vs}) == 3
    for v in vs:
        compile(v, "<variant>", "exec")
