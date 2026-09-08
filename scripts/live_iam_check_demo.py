"""Live cloud-posture check demonstration (charter success condition 6).

This runs AgentAudit's *real* read-only boto3 code path against an IAM role.

* With AWS credentials present it hits the real IAM API (``List*``/``Get*`` only)
  and prints the raw responses so a human can verify the verdict directly.
* With no credentials it drives the identical code path against a **clearly
  labeled** botocore Stubber, proving the check produces a correct pass/fail
  from a real boto3 response shape (scope-cut ladder item 4: a labeled mock,
  stated plainly — never implied to be live).

Usage:
    python scripts/live_iam_check_demo.py                 # auto: live if creds, else STUBBED
    python scripts/live_iam_check_demo.py --role my-role  # force live against a real role
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.layers import cloud_posture


def _stubbed_client(wildcard: bool):
    """A botocore IAM client backed by canned responses (LABELED MOCK)."""
    import urllib.parse

    import boto3
    from botocore.stub import Stubber

    client = boto3.client("iam", region_name="us-east-1",
                          aws_access_key_id="stub", aws_secret_access_key="stub")
    stub = Stubber(client)
    policy_doc = (
        {"Version": "2012-10-17",
         "Statement": [{"Sid": "Wide", "Effect": "Allow", "Action": "*", "Resource": "*"}]}
        if wildcard else
        {"Version": "2012-10-17",
         "Statement": [{"Sid": "Scoped", "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel"],
                        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/x"}]}
    )
    # On the wire IAM returns PolicyDocument as a URL-encoded JSON string;
    # boto3 auto-decodes it back to a dict for the caller.
    wire_doc = urllib.parse.quote(json.dumps(policy_doc))
    stub.add_response("list_role_policies", {"PolicyNames": ["inline"]},
                      {"RoleName": "demo-role"})
    stub.add_response("get_role_policy",
                      {"RoleName": "demo-role", "PolicyName": "inline", "PolicyDocument": wire_doc},
                      {"RoleName": "demo-role", "PolicyName": "inline"})
    stub.add_response("list_attached_role_policies", {"AttachedPolicies": []},
                      {"RoleName": "demo-role"})
    stub.activate()
    return client


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", help="real IAM role name (forces live mode)")
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    live = bool(args.role) or bool(os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"))

    if live:
        print(">>> LIVE mode: real read-only boto3 calls to IAM")
        role = args.role or "REPLACE_WITH_REAL_ROLE"
        findings, raw = cloud_posture.check_live_role(role, region=args.region)
    else:
        print(">>> STUBBED mode (LABELED MOCK - not a live AWS call)")
        print(">>> Driving the identical boto3 code path with canned IAM responses.\n")
        client = _stubbed_client(wildcard=True)
        findings, raw = cloud_posture.check_live_role("demo-role", iam_client=client)

    print("RAW boto3 responses (verify the verdict yourself):")
    print(json.dumps(raw, indent=2, default=str))
    print("\nVERDICT:")
    if findings:
        for f in findings:
            print(f"  [{f.severity.value.upper()}] {f.detector} @ {f.file}")
            print(f"      evidence: {f.evidence}")
    else:
        print("  PASS — role is least-privilege")
    return 0


if __name__ == "__main__":
    sys.exit(main())
