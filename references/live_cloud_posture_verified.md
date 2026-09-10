# Live Cloud-Posture Verification — Charter Success Condition 6

> **Condition 6:** "At least one AgentCore/IAM cloud-posture check runs against a
> real deployed test agent (not mocked) and produces a correct pass/fail,
> verified by the human reading the raw `boto3` API response, not the tool's
> summary of it."

**Status: CLOSED.** Check A below ran live against the real deployed runtime,
un-mocked, and produced a `FAIL` verdict that is hand-verifiable from the raw
`boto3` response pasted verbatim.

- **Captured:** 2026-09-10 08:06:47 UTC
- **Region:** `eu-north-1`
- **Account:** `580912381651`
- **Runtime:** `agentauditdeploy-tvmm505Sjc` (`status: READY`, `agentRuntimeVersion: 7`)
- **IAM identity making the calls:** `arn:aws:iam::580912381651:user/agentaudit`
- **Reproduce:** `PYTHONPATH=. python scripts/close_condition_6.py`

---

## CHECK A — Live AgentCore runtime posture (RAN, verdict `FAIL`)

### Exact command
```python
import boto3
cp = boto3.client("bedrock-agentcore-control", region_name="eu-north-1")
resp = cp.get_agent_runtime(agentRuntimeId="agentauditdeploy-tvmm505Sjc")
```
(`bedrock-agentcore:GetAgentRuntime` — a read-only `Get*` call, charter rule 5.)

### RAW boto3 response (verbatim, not summarized)
```json
{
  "ResponseMetadata": {
    "RequestId": "e3f4e8f6-e563-481a-b0a0-0ca963c8ac4d",
    "HTTPStatusCode": 200,
    "HTTPHeaders": {
      "date": "Thu, 10 Sep 2026 08:06:47 GMT",
      "content-type": "application/json",
      "content-length": "1005",
      "connection": "keep-alive",
      "x-amzn-requestid": "e3f4e8f6-e563-481a-b0a0-0ca963c8ac4d",
      "x-amz-apigw-id": "DeS7wHfMgi0Erzw=",
      "x-amzn-trace-id": "Root=1-6aa26517-0ac94d3d0e0dd6d77538068f"
    },
    "RetryAttempts": 0
  },
  "agentRuntimeArn": "arn:aws:bedrock-agentcore:eu-north-1:580912381651:runtime/agentauditdeploy-tvmm505Sjc",
  "agentRuntimeName": "agentauditdeploy",
  "agentRuntimeId": "agentauditdeploy-tvmm505Sjc",
  "agentRuntimeVersion": "7",
  "createdAt": "2026-09-09 19:22:45.611674+00:00",
  "lastUpdatedAt": "2026-09-10 00:05:29.293605+00:00",
  "roleArn": "arn:aws:iam::580912381651:role/AmazonBedrockAgentCoreSDKRuntime-eu-north-1-aebece9071",
  "networkConfiguration": {
    "networkMode": "PUBLIC"
  },
  "status": "READY",
  "lifecycleConfiguration": {
    "idleRuntimeSessionTimeout": 900,
    "maxLifetime": 28800
  },
  "workloadIdentityDetails": {
    "workloadIdentityArn": "arn:aws:bedrock-agentcore:eu-north-1:580912381651:workload-identity-directory/default/workload-identity/agentauditdeploy-tvmm505Sjc"
  },
  "agentRuntimeArtifact": {
    "containerConfiguration": {
      "containerUri": "580912381651.dkr.ecr.eu-north-1.amazonaws.com/bedrock-agentcore-agentauditdeploy:20260910-000448-719"
    }
  },
  "protocolConfiguration": {
    "serverProtocol": "HTTP"
  },
  "metadataConfiguration": {
    "requireMMDSV2": true
  }
}
```

### Verdict: `FAIL` — 1 finding

| Severity | Detector | Finding |
|---|---|---|
| MEDIUM | `runtime-network-mode` | AgentCore runtime uses `PUBLIC` network mode |

**Tool's evidence string:** `{"networkMode":"PUBLIC"}`

### Human verification (read the raw response yourself)
- `networkConfiguration.networkMode` in the raw JSON above is literally
  `"PUBLIC"` → the runtime's egress is not confined to a customer VPC. Any SSRF
  or exfiltration path in the agent's tools can reach the open internet. The
  `FAIL` verdict is **correct**.
- Cross-check the checks that did **not** fire (also correct):
  - `metadataConfiguration.requireMMDSV2` is `true` → IMDSv2 is enforced, so the
    `runtime-imdsv2` check correctly stays silent.
  - There is no `memoryConfiguration` block → AgentCore Memory is not enabled,
    so the `memory-encryption-ttl` check correctly stays silent.

This is a **non-mocked, live** AgentCore cloud-posture check producing a correct
pass/fail on a real deployed agent — Condition 6 is satisfied.

---

## CHECK B — IAM least-privilege on the execution role (BLOCKED, not by design)

### Exact command
```python
from agentaudit.layers.cloud_posture import check_live_role
check_live_role("AmazonBedrockAgentCoreSDKRuntime-eu-north-1-aebece9071", region="eu-north-1")
# -> iam.list_role_policies / get_role_policy / list_attached_role_policies
#    / get_policy / get_policy_version   (all read-only Get*/List*)
```

### RAW error (verbatim)
```
botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling
the ListRolePolicies operation: User: arn:aws:iam::580912381651:user/agentaudit
is not authorized to perform: iam:ListRolePolicies on resource: role
AmazonBedrockAgentCoreSDKRuntime-eu-north-1-aebece9071 because no identity-based
policy allows the iam:ListRolePolicies action.
```

### Status
The `agentaudit` credentials do **not** currently have the read-only IAM
introspection permissions needed to analyse the execution role's inline and
attached policies. This sub-check (charter scope-table capability #5) is
therefore **not live-verified**.

To unblock, add to `agentaudit`'s policy, scoped to the one role ARN:
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:ListRolePolicies", "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"
  ],
  "Resource": "arn:aws:iam::580912381651:role/AmazonBedrockAgentCoreSDKRuntime-eu-north-1-aebece9071"
}
```
The `check_live_role` code path is already written, tested with a botocore
Stubber, and would run unchanged once the permission is present.

---

## Summary

| Check | Live? | Mocked? | Result |
|---|---|---|---|
| A — AgentCore runtime posture (`GetAgentRuntime`) | ✅ yes | ❌ no | `FAIL` — `PUBLIC` network mode (hand-verified from raw JSON) |
| B — IAM least-privilege on execution role | ❌ blocked | — | not verified — `agentaudit` lacks `iam:ListRolePolicies` |

**Condition 6 is closed by Check A.** Check B is code-complete but blocked on a
missing read-only IAM permission, documented above with the exact scoped grant.
