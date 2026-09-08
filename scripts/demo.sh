#!/usr/bin/env bash
# The 5-minute demo sequence: vulnerable -> scan -> (fix) -> re-scan clean.
# Run from the repo root inside the venv.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python}"

echo
echo "################################################################"
echo "# 1. Integrity of the ground truth before we trust any result  #"
echo "################################################################"
./guard.sh check

echo
echo "################################################################"
echo "# 2. Audit the VULNERABLE agent  (expect: GRADE F, exit != 0)  #"
echo "################################################################"
set +e
$PY -m agentaudit run --agent fixtures/vulnerable_agent.py --out out/vuln
echo "exit code: $?"
set -e

echo
echo "################################################################"
echo "# 3. Audit the HARDENED agent    (expect: GRADE A, exit 0)     #"
echo "#    same agent family, every planted flaw fixed               #"
echo "################################################################"
$PY -m agentaudit run --agent fixtures/hardened_agent.py --out out/hard
echo "exit code: $?"

echo
echo "################################################################"
echo "# 4. Prove the clean report was not tampered with              #"
echo "################################################################"
$PY -m agentaudit verify --json out/hard/report.signed.json

echo
echo "Open out/vuln/scorecard.html and out/hard/scorecard.html for the visual."
