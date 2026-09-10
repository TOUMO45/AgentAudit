"""Probe real AgentCore gateway/policy state and current IAM capability.

Read-only. Prints exactly what exists and which calls are denied, so we build
against reality instead of assumptions.
"""

import boto3
import botocore

REGION = "eu-north-1"
cp = boto3.client("bedrock-agentcore-control", region_name=REGION)
iam = boto3.client("iam", region_name=REGION)


def probe(label, fn):
    try:
        r = fn()
        print(f"[OK]     {label}")
        return r
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print(f"[DENIED] {label} -> {code}")
        print(f"         {msg[:220]}")
        return None


print("=" * 72)
print("AGENTCORE CONTROL-PLANE STATE")
print("=" * 72)

gws = probe("ListGateways", lambda: cp.list_gateways(maxResults=20))
if gws is not None:
    items = gws.get("items", [])
    print(f"         gateways found: {len(items)}")
    for g in items:
        print("        ", {k: g.get(k) for k in ("gatewayId", "name", "status")})

pes = probe("ListPolicyEngines", lambda: cp.list_policyEngines(maxResults=20)
            if hasattr(cp, "list_policyEngines") else cp.list_policy_engines(maxResults=20))
if pes is not None:
    engines = pes.get("policyEngines", [])
    print(f"         policy engines found: {len(engines)}")
    for e in engines:
        print("        ", {k: e.get(k) for k in ("policyEngineId", "name", "status")})

print()
print("=" * 72)
print("IAM SELF-MANAGEMENT CAPABILITY")
print("=" * 72)
probe("iam:GetUserPolicy(agentaudit/AgentAuditInvokePolicy)",
      lambda: iam.get_user_policy(UserName="agentaudit", PolicyName="AgentAuditInvokePolicy"))
probe("iam:ListUserPolicies(agentaudit)",
      lambda: iam.list_user_policies(UserName="agentaudit"))
