"""Phase 2 — org-wide agent discovery.

Discovers every AgentCore agent runtime in the account so AgentAudit can scan
an entire estate rather than one hardcoded ARN.

Two sources, tried in order:

1. **AgentCore Agent Registry** (``ListRegistries`` / ``ListRegistryRecords``)
   — the curated registry, when the service is available in the region.
2. **AgentCore runtime inventory** (``ListAgentRuntimes``) — every deployed
   runtime in the account/region. This is the authoritative fallback and is
   what actually exists in eu-north-1.

Discovery never raises for a missing permission or unavailable service: it
records the reason on the result so the UI can show an honest state instead of
silently pretending zero agents exist.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

REGION = "eu-north-1"


@dataclass
class AgentRecord:
    """One discovered agent."""

    agent_id: str
    name: str
    arn: str
    status: str = "UNKNOWN"
    source: str = "runtime-inventory"  # or "agent-registry"
    description: str = ""
    updated_at: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d


@dataclass
class DiscoveryResult:
    """Discovery outcome, including *why* it is empty when it is."""

    agents: list[AgentRecord] = field(default_factory=list)
    source: str = "none"
    available: bool = False
    reason: str = ""
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> dict:
        return {
            "agents": [a.to_dict() for a in self.agents],
            "count": len(self.agents),
            "source": self.source,
            "available": self.available,
            "reason": self.reason,
            "discovered_at": self.discovered_at,
        }


def _client(name: str, client=None):
    if client is not None:
        return client
    import boto3

    return boto3.client(name, region_name=REGION)


def _from_runtime_inventory(cp) -> tuple[list[AgentRecord], str]:
    """ListAgentRuntimes -> AgentRecord list. Returns (agents, raw_error)."""
    import botocore

    agents: list[AgentRecord] = []
    try:
        paginator = None
        try:
            paginator = cp.get_paginator("list_agent_runtimes")
        except Exception:
            paginator = None

        pages = paginator.paginate() if paginator else [cp.list_agent_runtimes(maxResults=100)]
        for page in pages:
            for item in page.get("agentRuntimes", []) or page.get("items", []):
                agents.append(
                    AgentRecord(
                        agent_id=item.get("agentRuntimeId", ""),
                        name=item.get("agentRuntimeName") or item.get("name", ""),
                        arn=item.get("agentRuntimeArn", ""),
                        status=item.get("status", "UNKNOWN"),
                        source="runtime-inventory",
                        description=item.get("description", "") or "",
                        updated_at=str(item.get("lastUpdatedAt", "")),
                        raw=item,
                    )
                )
        return agents, ""
    except botocore.exceptions.ClientError as e:
        return [], f"{e.response['Error']['Code']}: {e.response['Error']['Message'][:200]}"
    except Exception as e:  # service not routable in region, etc.
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def _from_agent_registry(cp) -> tuple[list[AgentRecord], str]:
    """Agent Registry, when the service is available in this region."""
    ops = cp.meta.service_model.operation_names
    if "ListRegistries" not in ops:
        return [], "ListRegistries not present in this API version"
    try:
        regs = cp.list_registries(maxResults=20)
    except Exception as e:
        return [], f"{type(e).__name__}: {str(e)[:200]}"

    agents: list[AgentRecord] = []
    for reg in regs.get("registries", []) or regs.get("items", []):
        rid = reg.get("registryId") or reg.get("id")
        if not rid:
            continue
        try:
            recs = cp.list_registry_records(registryIdentifier=rid, maxResults=100)
        except Exception:
            continue
        for r in recs.get("registryRecords", []) or recs.get("items", []):
            agents.append(
                AgentRecord(
                    agent_id=r.get("registryRecordId", ""),
                    name=r.get("name", ""),
                    arn=r.get("targetArn") or r.get("arn", ""),
                    status=r.get("status", "UNKNOWN"),
                    source="agent-registry",
                    description=r.get("description", "") or "",
                    raw=r,
                )
            )
    return agents, ""


def list_registered_agents(client=None, prefer_registry: bool = True) -> DiscoveryResult:
    """Return every agent AgentAudit can discover in this account/region."""
    cp = _client("bedrock-agentcore-control", client)
    reasons: list[str] = []

    if prefer_registry:
        agents, err = _from_agent_registry(cp)
        if agents:
            return DiscoveryResult(agents, "agent-registry", True, "")
        if err:
            reasons.append(f"agent-registry unavailable ({err})")

    agents, err = _from_runtime_inventory(cp)
    if agents:
        return DiscoveryResult(agents, "runtime-inventory", True, "; ".join(reasons))
    if err:
        reasons.append(f"runtime-inventory unavailable ({err})")
        return DiscoveryResult([], "none", False, "; ".join(reasons))

    # Service reachable, genuinely zero agents.
    return DiscoveryResult([], "runtime-inventory", True,
                           "no agent runtimes exist in this account/region")


def summarize(per_agent: dict[str, list[Any]]) -> dict:
    """Aggregate severity counts across agents.

    The org-wide totals are computed here so a test can assert they equal the
    sum of the per-agent numbers.
    """
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    per_agent_counts: dict[str, dict] = {}

    for agent_key, findings in per_agent.items():
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f, "severity") else f.get("severity")
            if sev in counts:
                counts[sev] += 1
        per_agent_counts[agent_key] = counts
        for k, v in counts.items():
            totals[k] += v

    return {
        "totals": totals,
        "per_agent": per_agent_counts,
        "agent_count": len(per_agent),
        "total_findings": sum(totals.values()),
    }
