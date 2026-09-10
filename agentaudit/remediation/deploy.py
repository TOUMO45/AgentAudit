"""Deploy generated Cedar policies to AgentCore Policy (real control-plane API).

Uses the verified ``bedrock-agentcore-control`` operations:

* ``CreatePolicy(policyEngineId, name, definition={'cedar': {'statement': ...}},
  enforcementMode=..., validationMode=...)``
* ``GetPolicy(policyEngineId, policyId)`` to confirm status
* ``GetGateway(gatewayIdentifier)`` to resolve a gateway's policy engine

Every generated policy is written to ``policies/generated/<finding_id>.cedar``
with a sidecar ``.json`` recording the deployment result, so there is an audit
trail regardless of whether the deploy was live or a dry run.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REGION = "eu-north-1"
POLICY_DIR = Path("policies/generated")
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


@dataclass
class DeployResult:
    """Outcome of a policy deployment attempt."""

    status: str  # "dry-run" | "active" | "log-only" | "error"
    dry_run: bool
    policy_name: str
    finding_id: str
    policy_id: str | None = None
    policy_arn: str | None = None
    policy_engine_id: str | None = None
    api_status: str | None = None
    enforcement_mode: str | None = None
    error: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_id(finding_id: str) -> str:
    return _SAFE.sub("_", finding_id)[:120]


def write_policy_file(
    finding_id: str,
    policy_text: str,
    result: DeployResult | None = None,
    policy_dir: Path | str = POLICY_DIR,
) -> Path:
    """Persist the Cedar text (and deployment result) for audit purposes."""
    d = Path(policy_dir)
    d.mkdir(parents=True, exist_ok=True)
    stem = _safe_id(finding_id)
    cedar_path = d / f"{stem}.cedar"
    cedar_path.write_text(policy_text, encoding="utf-8")
    if result is not None:
        (d / f"{stem}.json").write_text(
            json.dumps(result.to_dict(), indent=2), encoding="utf-8"
        )
    return cedar_path


def resolve_policy_engine(gateway_id: str, client=None) -> str | None:
    """Look up the policy engine attached to a gateway (real GetGateway call)."""
    import boto3

    cp = client or boto3.client("bedrock-agentcore-control", region_name=REGION)
    gw = cp.get_gateway(gatewayIdentifier=gateway_id)
    cfg = gw.get("policyEngineConfiguration") or {}
    return cfg.get("policyEngineId") or cfg.get("policyEngineArn")


def deploy_cedar_policy(
    policy_text: str,
    gateway_id: str,
    finding_id: str = "unknown",
    policy_name: str | None = None,
    policy_engine_id: str | None = None,
    dry_run: bool = True,
    enforcement_mode: str = "ACTIVE",
    client=None,
) -> DeployResult:
    """Submit a Cedar policy to AgentCore Policy.

    ``dry_run=True`` (the default) writes the policy to disk and validates
    inputs without calling the mutating API. Flip to ``False`` to deploy live.
    """
    name = policy_name or f"agentaudit-{_safe_id(finding_id)}"[:64]

    if dry_run:
        result = DeployResult(
            status="dry-run",
            dry_run=True,
            policy_name=name,
            finding_id=finding_id,
            policy_engine_id=policy_engine_id,
            enforcement_mode=enforcement_mode,
        )
        write_policy_file(finding_id, policy_text, result)
        return result

    import boto3
    import botocore

    cp = client or boto3.client("bedrock-agentcore-control", region_name=REGION)
    try:
        engine = policy_engine_id or resolve_policy_engine(gateway_id, cp)
        if not engine:
            raise ValueError(
                f"no policy engine resolved for gateway {gateway_id!r}; "
                "pass policy_engine_id explicitly"
            )

        resp = cp.create_policy(
            policyEngineId=engine,
            name=name,
            description=f"AgentAudit auto-remediation for finding {finding_id}",
            definition={"cedar": {"statement": policy_text}},
            enforcementMode=enforcement_mode,
            validationMode="FAIL_ON_ANY_FINDINGS",
        )
        result = DeployResult(
            status="active" if enforcement_mode == "ACTIVE" else "log-only",
            dry_run=False,
            policy_name=name,
            finding_id=finding_id,
            policy_id=resp.get("policyId"),
            policy_arn=resp.get("policyArn"),
            policy_engine_id=engine,
            api_status=resp.get("status"),
            enforcement_mode=resp.get("enforcementMode", enforcement_mode),
        )
    except (botocore.exceptions.ClientError, ValueError) as e:
        result = DeployResult(
            status="error",
            dry_run=False,
            policy_name=name,
            finding_id=finding_id,
            policy_engine_id=policy_engine_id,
            enforcement_mode=enforcement_mode,
            error=f"{type(e).__name__}: {e}",
        )

    write_policy_file(finding_id, policy_text, result)
    return result


def remediate_findings(
    findings: list[Any],
    gateway_arn: str,
    gateway_id: str,
    target_name: str = "AgentAudit",
    dry_run: bool = True,
    min_severity: tuple[str, ...] = ("critical", "high"),
    policy_dir: Path | str = POLICY_DIR,
) -> list[DeployResult]:
    """Generate + deploy Cedar policies for every HIGH/CRITICAL finding.

    This is the hook the static-analysis stage calls.
    """
    from agentaudit.remediation.cedar import generate_cedar_policy, policy_name_for

    results: list[DeployResult] = []
    for f in findings:
        sev = f.severity.value if hasattr(f, "severity") else f.get("severity")
        if sev not in min_severity:
            continue
        fid = f.fingerprint if hasattr(f, "fingerprint") else f.get("fingerprint", "unknown")
        text = generate_cedar_policy(f, gateway_arn=gateway_arn, target_name=target_name)
        res = deploy_cedar_policy(
            text,
            gateway_id=gateway_id,
            finding_id=fid,
            policy_name=policy_name_for(f),
            dry_run=dry_run,
        )
        # keep the audit file in the requested directory
        if str(policy_dir) != str(POLICY_DIR):
            write_policy_file(fid, text, res, policy_dir)
        results.append(res)
    return results
