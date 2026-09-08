#!/usr/bin/env bash
# AgentAudit integrity guard (charter success condition 5).
#
# The ground truth (fixtures + MANIFEST) and the detection/scoring code are the
# trust anchors of a security tool. This guard freezes their SHA-256 hashes and
# later proves nothing changed "behind the human's back". If a check fails
# against a fixture, the rule is: fix the detector, never the fixture.
#
#   ./guard.sh freeze   # after human sign-off: record the trusted hashes
#   ./guard.sh check    # in CI / before a run: verify nothing was tampered with
#
# `check` prints "INTEGRITY OK" when clean, or the exact tampered path and its
# diff and exits non-zero.
set -euo pipefail

cd "$(dirname "$0")"
BASELINE=".agentaudit_integrity.sha256"

# Protected set: all ground-truth fixtures + the scorer/detector code.
collect_paths() {
  find fixtures -type f | sort
  cat <<'EOF'
agentaudit/scorer.py
agentaudit/models.py
agentaudit/layers/static_graph.py
agentaudit/layers/cloud_posture.py
agentaudit/layers/behavioral.py
agentaudit/layers/supply_chain.py
EOF
}

hash_all() {
  collect_paths | while IFS= read -r p; do
    [ -f "$p" ] && sha256sum "$p"
  done
}

case "${1:-}" in
  freeze)
    hash_all > "$BASELINE"
    echo "Froze $(wc -l < "$BASELINE") protected paths into $BASELINE"
    ;;
  check)
    if [ ! -f "$BASELINE" ]; then
      echo "NO BASELINE: run './guard.sh freeze' after human sign-off first." >&2
      exit 2
    fi
    # sha256sum -c reports "<path>: OK|FAILED"; capture failures.
    if out=$(sha256sum -c "$BASELINE" 2>/dev/null); then
      # Also detect additions/removals from the protected set.
      # Extract paths from the baseline (format: "<hash> *<path>").
      baseline_paths=$(sed 's/^[0-9a-f]\{64\} [ *]//' "$BASELINE" | sort)
      current_paths=$(collect_paths | while read -r p; do [ -f "$p" ] && echo "$p"; done | sort)
      if diff <(echo "$baseline_paths") <(echo "$current_paths") >/dev/null; then
        echo "INTEGRITY OK"
        exit 0
      fi
    fi
    echo "INTEGRITY VIOLATION" >&2
    echo "$out" | grep -v ': OK$' || true
    while IFS= read -r line; do
      case "$line" in
        *": FAILED"*)
          path="${line%: FAILED}"
          echo "--- tampered: $path" >&2
          git diff -- "$path" 2>/dev/null | sed 's/^/    /' >&2 || true
          ;;
      esac
    done <<< "$out"
    exit 1
    ;;
  *)
    echo "usage: ./guard.sh {freeze|check}" >&2
    exit 2
    ;;
esac
