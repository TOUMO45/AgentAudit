"""Charter Success Condition 6 — live AgentCore/IAM cloud-posture check against
the real deployed runtime. No mocks. Read-only APIs only (Get*/List*)."""

import datetime
import json
import sys

import boto3
import botocore

from agentaudit.layers.cloud_posture import check_live_role, check_live_runtime

REGION = "eu-north-1"
RUNTIME_ID = "agentauditdeploy-tvmm505Sjc"
NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

bundle = {"captured_at": NOW, "region": REGION, "runtime_id": RUNTIME_ID, "checks": {}}
cp = boto3.client("bedrock-agentcore-control", region_name=REGION)

# ==========================================================================
# CHECK A — AgentCore runtime posture (GetAgentRuntime, read-only)
# ==========================================================================
print("=" * 72)
print("CHECK A: live AgentCore runtime posture  (bedrock-agentcore:GetAgentRuntime)")
print("=" * 72)
try:
    findings_a, raw_a = check_live_runtime(RUNTIME_ID, region=REGION, cp_client=cp)
    verdict_a = "FAIL" if findings_a else "PASS"
    bundle["checks"]["A_runtime_posture"] = {
        "command": f"boto3.client('bedrock-agentcore-control', region_name='{REGION}')"
                   f".get_agent_runtime(agentRuntimeId='{RUNTIME_ID}')",
        "raw_boto3_response": raw_a,
        "findings": [f.to_dict() for f in findings_a],
        "verdict": verdict_a,
    }
    print(f"  verdict: {verdict_a}  ({len(findings_a)} finding(s))")
    for f in findings_a:
        print(f"    [{f.severity.value.upper()}] {f.detector}")
        print(f"      {f.title}")
        print(f"      evidence: {f.evidence}")
except botocore.exceptions.ClientError as e:
    bundle["checks"]["A_runtime_posture"] = {"error": str(e), "verdict": "UNVERIFIED"}
    print(f"  DENIED/ERROR: {e}")

# ==========================================================================
# CHECK B — IAM least-privilege on the runtime's execution role
# ==========================================================================
print()
print("=" * 72)
print("CHECK B: IAM least-privilege on the runtime execution role  (iam:Get*/List*)")
print("=" * 72)
role_arn = ""
try:
    gar = cp.get_agent_runtime(agentRuntimeId=RUNTIME_ID)
    role_arn = gar.get("roleArn", "")
except botocore.exceptions.ClientError:
    pass
role_name = role_arn.split("/")[-1] if role_arn else ""
print(f"  execution role: {role_arn or '(unresolved)'}")
if role_name:
    try:
        findings_b, raw_b = check_live_role(role_name, region=REGION)
        verdict_b = "FAIL" if findings_b else "PASS"
        bundle["checks"]["B_iam_least_privilege"] = {
            "command": f"check_live_role('{role_name}')  -> iam list_role_policies / "
                       f"get_role_policy / list_attached_role_policies / get_policy / "
                       f"get_policy_version",
            "raw_boto3_response": json.loads(json.dumps(raw_b, default=str)),
            "findings": [f.to_dict() for f in findings_b],
            "verdict": verdict_b,
        }
        print(f"  verdict: {verdict_b}  ({len(findings_b)} finding(s))")
        for f in findings_b:
            print(f"    [{f.severity.value.upper()}] {f.detector}  {f.file}")
    except botocore.exceptions.ClientError as e:
        bundle["checks"]["B_iam_least_privilege"] = {
            "command": f"check_live_role('{role_name}')",
            "error": e.response["Error"]["Code"] + ": " + e.response["Error"]["Message"],
            "verdict": "BLOCKED — agentaudit creds lack iam:ListRolePolicies on this role",
        }
        print(f"  BLOCKED: {e.response['Error']['Code']}")
        print(f"    {e.response['Error']['Message']}")

out = "references/_condition6_raw.json"
with open(out, "w", encoding="utf-8") as fh:
    json.dump(bundle, fh, indent=2, default=str)
print(f"\nraw bundle -> {out}")
sys.exit(0)
