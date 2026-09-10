# Live Org-Wide Discovery + Scan — Phase 2 (Step 3)

Discovery (Agent Registry → `ListAgentRuntimes` fallback) and the org-wide
Layer-3 scan, run live against account `580912381651` in `eu-north-1`.

- **Captured:** 2026-09-10 08:18–08:19 UTC
- **IAM identity:** `arn:aws:iam::580912381651:user/agentaudit`
- **Reproduce:** `PYTHONPATH=. python scripts/step3_org_scan.py`

---

## 1. RAW `list_agent_runtimes` response (verbatim)

```
boto3.client("bedrock-agentcore-control", region_name="eu-north-1")
    .list_agent_runtimes(maxResults=100)
```

```json
{
  "ResponseMetadata": {
    "RequestId": "1f4fa52a-f597-4e8e-a6d3-d6ba2f5c828b",
    "HTTPStatusCode": 200,
    "HTTPHeaders": {
      "date": "Thu, 10 Sep 2026 08:18:47 GMT",
      "content-type": "application/json",
      "content-length": "304",
      "x-amzn-requestid": "1f4fa52a-f597-4e8e-a6d3-d6ba2f5c828b",
      "x-amz-apigw-id": "DeUsPHSVgi0EbBA=",
      "x-amzn-trace-id": "Root=1-6aa267e7-3cd9d49d7b987c55480a72ce"
    },
    "RetryAttempts": 0
  },
  "agentRuntimes": [
    {
      "agentRuntimeArn": "arn:aws:bedrock-agentcore:eu-north-1:580912381651:runtime/agentauditdeploy-tvmm505Sjc",
      "agentRuntimeId": "agentauditdeploy-tvmm505Sjc",
      "agentRuntimeVersion": "7",
      "agentRuntimeName": "agentauditdeploy",
      "lastUpdatedAt": "2026-09-10 00:05:29.293605+00:00",
      "status": "READY"
    }
  ]
}
```

**One agent exists in this account/region.** The Agent Registry path
(`ListRegistries`) is not routable in `eu-north-1` ("Unable to determine
service/operation name to be authorized"), so discovery correctly falls back to
the runtime inventory — `available: true`, `source: "runtime-inventory"`.

## 2. Discovery mapping

```json
{
  "agents": [
    {
      "agent_id": "agentauditdeploy-tvmm505Sjc",
      "name": "agentauditdeploy",
      "arn": "arn:aws:bedrock-agentcore:eu-north-1:580912381651:runtime/agentauditdeploy-tvmm505Sjc",
      "status": "READY",
      "source": "runtime-inventory",
      "updated_at": "2026-09-10 00:05:29.293605+00:00"
    }
  ],
  "count": 1,
  "source": "runtime-inventory",
  "available": true
}
```

**ID cross-check:** raw runtime IDs `['agentauditdeploy-tvmm505Sjc']` ==
discovery IDs `['agentauditdeploy-tvmm505Sjc']` → **MATCH**.

## 3. Org-wide Layer-3 scan

Discovered agents are deployed *runtimes* with no source, so the org-wide scan
runs Layer 3 (`check_live_runtime` → `GetAgentRuntime` posture) against each.
Layer 2 (static trust graph) runs against source files — see the per-file
dashboard scans and `real_world_findings.md`.

```
GetAgentRuntime(agentauditdeploy-tvmm505Sjc)  RequestId 8b2e673d-ab83-42aa-bc14-0c71d4084cf8  HTTP 200
```

### Per-agent findings

| Agent | Severity | Detector | Finding |
|---|---|---|---|
| `agentauditdeploy-tvmm505Sjc` | MEDIUM | `runtime-network-mode` | AgentCore runtime uses PUBLIC network mode |

### Aggregation hand-check (assertions, not a visual check)

```
org totals: {critical: 0, high: 0, medium: 1, low: 0, info: 0}
per_agent : {agentauditdeploy-tvmm505Sjc: {critical: 0, high: 0, medium: 1, low: 0, info: 0}}

  totals[critical] == sum(per_agent) -> 0 == 0  OK
  totals[high]     == sum(per_agent) -> 0 == 0  OK
  totals[medium]   == sum(per_agent) -> 1 == 1  OK   <- hand-checked agent
  totals[low]      == sum(per_agent) -> 0 == 0  OK
  totals[info]     == sum(per_agent) -> 0 == 0  OK
  total_findings   == sum(totals)    -> 1 == 1  OK

ORG AGGREGATION VERIFIED
```

**Hand-check of `agentauditdeploy-tvmm505Sjc`:** the raw `GetAgentRuntime`
response for this agent contains `"networkConfiguration": {"networkMode":
"PUBLIC"}` and no other posture issue (`requireMMDSV2: true`, no memory block).
The scan reports exactly one MEDIUM finding for it, and the org `medium` total
is exactly 1 — the aggregation matches the raw data.

---

## Status

| Item | Result |
|---|---|
| `list_registered_agents()` returns the real `agentauditdeploy` agent | ✅ raw response pasted above |
| Each agent gets its own findings (not duplicated) | ✅ 1 agent, 1 finding, sourced from its own `GetAgentRuntime` |
| Aggregate == sum of per-agent (assertion, not visual) | ✅ 6/6 assertions pass |
| Zero-agents empty state | covered by `tests/test_phase2_discovery.py::test_zero_agents_is_an_honest_empty_state` |

**Phase 2 org-wide discovery + scan is LIVE-VERIFIED.**
