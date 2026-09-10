"""Phase 1 end-to-end: scan -> capability findings -> Cedar -> dry-run deploy."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.layers.capability_graph import analyze_capability_pairs  # noqa: E402
from agentaudit.remediation.deploy import remediate_findings  # noqa: E402

GATEWAY_ARN = sys.argv[1] if len(sys.argv) > 1 else "<gateway-arn-pending>"
GATEWAY_ID = sys.argv[2] if len(sys.argv) > 2 else "pending"

findings = analyze_capability_pairs("fixtures/exfil/exfil_agent.py")
print(f"static analyzer produced {len(findings)} capability-pair finding(s)\n")
for f in findings:
    print(f"  [{f.severity.value.upper():8}] {f.detector} :: {f.metadata['pattern']}")
    print(f"            {f.metadata['tool_a']} + {f.metadata['tool_b']}")

print("\n" + "=" * 70)
print("GENERATING + DEPLOYING (dry-run) CEDAR POLICIES FOR HIGH/CRITICAL")
print("=" * 70)

results = remediate_findings(
    findings, gateway_arn=GATEWAY_ARN, gateway_id=GATEWAY_ID, dry_run=True
)
for r in results:
    print(f"\n  policy_name : {r.policy_name}")
    print(f"  status      : {r.status}")
    print(f"  finding_id  : {r.finding_id}")

print("\n" + "=" * 70)
print("FILES WRITTEN TO DISK")
print("=" * 70)
for p in sorted(Path("policies/generated").glob("*.cedar")):
    print(f"\n--- {p} ---")
    print(p.read_text(encoding="utf-8"))
