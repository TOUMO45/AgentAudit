"""Step 3 — live org-wide discovery + scan evidence.

1. Raw boto3 list_agent_runtimes response (verbatim).
2. Discovery mapping (AgentRecord list).
3. Org-wide scan: statically audit each discovered agent whose source is
   locally available; hand-check the aggregation against raw per-agent counts.
"""

import datetime
import json

import boto3

from agentaudit.discovery import list_registered_agents

REGION = "eu-north-1"
NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

evidence = {"captured_at": NOW, "region": REGION}

# --- 1. raw list_agent_runtimes -----------------------------------------
cp = boto3.client("bedrock-agentcore-control", region_name=REGION)
raw = cp.list_agent_runtimes(maxResults=100)
evidence["raw_list_agent_runtimes"] = json.loads(json.dumps(raw, default=str))
print("=" * 72)
print("[1] RAW boto3 list_agent_runtimes response")
print("=" * 72)
print(json.dumps(evidence["raw_list_agent_runtimes"], indent=2))

# --- 2. discovery mapping ---------------------------------------------
disc = list_registered_agents()
evidence["discovery_result"] = disc.to_dict()
print()
print("=" * 72)
print("[2] Discovery mapping")
print("=" * 72)
print(json.dumps(disc.to_dict(), indent=2))

# --- 3. cross-check: raw count == discovery count --------------------
raw_ids = [r.get("agentRuntimeId") for r in raw.get("agentRuntimes", [])]
disc_ids = [a["agent_id"] for a in disc.to_dict()["agents"]]
print()
print("=" * 72)
print("[3] Hand-check: raw runtime IDs vs discovery IDs")
print("=" * 72)
print(f"  raw ({len(raw_ids)}):       {raw_ids}")
print(f"  discovery ({len(disc_ids)}): {disc_ids}")
match = sorted(raw_ids) == sorted(disc_ids)
print(f"  MATCH: {match}")
evidence["id_crosscheck"] = {"raw_ids": raw_ids, "discovery_ids": disc_ids, "match": match}

out = "references/_step3_org_scan_raw.json"
with open(out, "w", encoding="utf-8") as fh:
    json.dump(evidence, fh, indent=2, default=str)
print(f"\nraw evidence -> {out}")
