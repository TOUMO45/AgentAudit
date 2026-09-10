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
# Hashes are computed over LINE-ENDING-NORMALIZED content (CR stripped) so the
# baseline is identical on Windows (CRLF) and Linux/CI (LF) — the repo uses
# `.gitattributes eol=lf`, so a naive byte hash would differ per platform.
#
# `check` prints "INTEGRITY OK" when clean, or the exact tampered path and its
# diff and exits non-zero.
set -euo pipefail

cd "$(dirname "$0")"
BASELINE=".agentaudit_integrity.sha256"

# Protected set: all ground-truth fixtures + the scorer/detector code.
collect_paths() {
  # Only committed source — never build artifacts (__pycache__/*.pyc are
  # gitignored and absent on a clean CI checkout, so including them would make
  # the baseline non-portable).
  find fixtures -type f -not -path '*/__pycache__/*' -not -name '*.pyc' | sort
  cat <<'EOF'
agentaudit/scorer.py
agentaudit/models.py
agentaudit/layers/static_graph.py
agentaudit/layers/cloud_posture.py
agentaudit/layers/behavioral.py
agentaudit/layers/supply_chain.py
agentaudit/layers/capability_graph.py
agentaudit/layers/harness_integrity.py
agentaudit/remediation/cedar.py
agentaudit/remediation/deploy.py
EOF
}

# Normalized hash: strip carriage returns, then sha256 the content.
norm_hash() {
  tr -d '\r' < "$1" | sha256sum | cut -d' ' -f1
}

existing_paths() {
  collect_paths | while IFS= read -r p; do [ -f "$p" ] && echo "$p"; done | sort
}

freeze() {
  : > "$BASELINE"
  existing_paths | while IFS= read -r p; do
    echo "$(norm_hash "$p")  $p" >> "$BASELINE"
  done
  echo "Froze $(wc -l < "$BASELINE" | tr -d ' ') protected paths into $BASELINE"
}

check() {
  if [ ! -f "$BASELINE" ]; then
    echo "NO BASELINE: run './guard.sh freeze' after human sign-off first." >&2
    exit 2
  fi

  violation=0

  # 1) added / removed protected paths
  baseline_paths=$(cut -d' ' -f3- "$BASELINE" | sort)
  current_paths=$(existing_paths)
  if ! diff <(echo "$baseline_paths") <(echo "$current_paths") >/dev/null; then
    violation=1
    echo "INTEGRITY VIOLATION: protected file set changed" >&2
    diff <(echo "$baseline_paths") <(echo "$current_paths") | sed 's/^/    /' >&2 || true
  fi

  # 2) content changes (normalized hash mismatch)
  while IFS= read -r line; do
    expected="${line%%  *}"
    path="${line#*  }"
    if [ ! -f "$path" ]; then continue; fi
    actual="$(norm_hash "$path")"
    if [ "$expected" != "$actual" ]; then
      violation=1
      echo "INTEGRITY VIOLATION: content changed -> $path" >&2
      git diff -- "$path" 2>/dev/null | sed 's/^/    /' >&2 || true
    fi
  done < "$BASELINE"

  if [ "$violation" -eq 0 ]; then
    echo "INTEGRITY OK"
    exit 0
  fi
  exit 1
}

case "${1:-}" in
  freeze) freeze ;;
  check) check ;;
  *) echo "usage: ./guard.sh {freeze|check}" >&2; exit 2 ;;
esac
