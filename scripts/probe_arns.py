"""Capture the exact resource ARN AWS reports for each action we need.

Read-only probes only. Each AccessDenied message names the precise resource ARN
IAM evaluated, so we can scope the policy to real ARNs instead of guessing.
"""

import re

import boto3
import botocore

REGION = "eu-north-1"
cp = boto3.client("bedrock-agentcore-control", region_name=REGION)
dp = boto3.client("bedrock-agentcore", region_name=REGION)

PROBES = [
    ("bedrock-agentcore:ListGateways", lambda: cp.list_gateways(maxResults=5)),
    ("bedrock-agentcore:ListPolicyEngines", lambda: cp.list_policy_engines(maxResults=5)),
    ("bedrock-agentcore:ListAgentRuntimes", lambda: cp.list_agent_runtimes(maxResults=5)),
    ("bedrock-agentcore:ListEvaluators", lambda: cp.list_evaluators(maxResults=5)),
    ("bedrock-agentcore:ListBatchEvaluations", lambda: dp.list_batch_evaluations(maxResults=5)),
]

# Registry listing op name varies; discover it dynamically.
ops = cp.meta.service_model.operation_names
if "ListRegistries" in ops:
    PROBES.append(("bedrock-agentcore:ListRegistries", lambda: cp.list_registries(maxResults=5)))
else:
    print("note: ListRegistries not in API; registry ops available:",
          [o for o in ops if "Registr" in o])

pat = re.compile(r"on resource:\s*(\S+)")
results = {}

for action, fn in PROBES:
    try:
        r = fn()
        print(f"[ALLOWED] {action}")
        results[action] = ("ALLOWED", r)
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        m = pat.search(msg)
        arn = m.group(1).rstrip(".") if m else "(no resource in message)"
        print(f"[{code}] {action}")
        print(f"          resource: {arn}")
        results[action] = (code, arn)
    except Exception as e:
        print(f"[ERROR] {action} -> {type(e).__name__}: {str(e)[:150]}")

print()
print("=" * 70)
print("ALLOWED actions:", [a for a, (s, _) in results.items() if s == "ALLOWED"])
