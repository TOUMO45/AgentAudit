"""Verify the severity palette is colorblind-distinguishable (Phase 2 item 2.7).

Simulates protanopia / deuteranopia / tritanopia (Machado et al. 2009 matrices
applied in linear RGB) and reports the minimum pairwise CIE76 ΔE between the four
severity colors under each condition. We require every pair to stay above a
distinguishability threshold under every simulation — "tested with a simulator,
not by eye" as the loop demands.
"""

from __future__ import annotations

# Severity palette (verified below). Tuned so red/orange/yellow separate by
# luminance as well as hue, which is what survives red-green color blindness.
PALETTE = {
    "critical": "#F0486B",  # crimson-rose red
    "high": "#D9772A",      # deep orange
    "medium": "#F6EC72",    # pale bright yellow
    "low": "#57A8F6",       # blue
}

_MACHADO = {
    "protanopia": [
        [0.152286, 1.052583, -0.204868],
        [0.114503, 0.786281, 0.099216],
        [-0.003882, -0.048116, 1.051998],
    ],
    "deuteranopia": [
        [0.367322, 0.860646, -0.227968],
        [0.280085, 0.672501, 0.047413],
        [-0.011820, 0.042940, 0.968881],
    ],
    "tritanopia": [
        [1.255528, -0.076749, -0.178779],
        [-0.078411, 0.930809, 0.147602],
        [0.004733, 0.691367, 0.303900],
    ],
}


def _hex_to_rgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore


def _srgb_to_linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _linear_to_srgb(c: float) -> float:
    c = max(0.0, min(1.0, c))
    return c * 12.92 if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def _matmul(m, v):
    return [sum(m[r][c] * v[c] for c in range(3)) for r in range(3)]


def simulate(hexcolor: str, kind: str) -> tuple[float, float, float]:
    lin = [_srgb_to_linear(c) for c in _hex_to_rgb(hexcolor)]
    out = _matmul(_MACHADO[kind], lin)
    return tuple(_linear_to_srgb(c) for c in out)  # type: ignore


def _rgb_to_lab(rgb: tuple[float, float, float]):
    r, g, b = (_srgb_to_linear(c) for c in rgb)
    x = r * 0.4124 + g * 0.3576 + b * 0.1805
    y = r * 0.2126 + g * 0.7152 + b * 0.0722
    z = r * 0.0193 + g * 0.1192 + b * 0.9505
    x, y, z = x / 0.95047, y / 1.0, z / 1.08883

    def f(t):
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def _delta_e(c1, c2) -> float:
    l1 = _rgb_to_lab(c1)
    l2 = _rgb_to_lab(c2)
    return sum((a - b) ** 2 for a, b in zip(l1, l2)) ** 0.5


THRESHOLD = 15.0  # CIE76 ΔE; > ~15 is comfortably distinguishable


def evaluate(palette: dict[str, str] = PALETTE) -> dict[str, float]:
    names = list(palette)
    results: dict[str, float] = {}
    for kind in ("normal", *_MACHADO):
        sim = {
            n: _hex_to_rgb(palette[n]) if kind == "normal" else simulate(palette[n], kind)
            for n in names
        }
        min_de = min(
            _delta_e(sim[a], sim[b])
            for i, a in enumerate(names) for b in names[i + 1:]
        )
        results[kind] = min_de
    return results


def main() -> int:
    results = evaluate()
    print("Minimum pairwise CIE76 ΔE between severity colors:")
    ok = True
    for kind, de in results.items():
        status = "PASS" if de >= THRESHOLD else "FAIL"
        ok = ok and de >= THRESHOLD
        print(f"  {kind:<12} min ΔE = {de:6.1f}  [{status}]")
    print(f"\nthreshold = {THRESHOLD}  ->  {'ALL DISTINGUISHABLE' if ok else 'PALETTE FAILS'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
