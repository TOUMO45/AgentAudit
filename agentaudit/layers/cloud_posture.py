"""Layer 3 — AWS Cloud Posture Checker (AgentCore / IAM).

Two modes, same detectors:

* **offline** — analyze a deployment descriptor (``<agent>.deploy.json``,
  auto-discovered next to the agent). Deterministic; used in the demo and CI.
* **live** — read-only ``boto3`` calls (``Get*``/``List*`` only, never a mutating
  API — charter rule 5) against a real AgentCore/IAM deployment. Returns the raw
  API responses so a human can verify the verdict against the source of truth
  (charter success condition 6), not just the tool's summary.

Checks: IAM least-privilege on the execution role, Bedrock Guardrails
attached-and-active, and AgentCore Memory encryption + TTL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentaudit.models import Confidence, Finding, Layer, LayerReport, Remediation, Severity


# ---------------------------------------------------------------------------
# Shared policy analysis (used by both offline and live modes)
# ---------------------------------------------------------------------------
def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def policy_findings(policy_doc: dict, source: str) -> list[Finding]:
    """Flag Allow statements that grant Action ``*`` or Resource ``*``."""
    findings: list[Finding] = []
    for stmt in _as_list(policy_doc.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))
        wildcard_action = any(a == "*" or a.endswith(":*") for a in actions)
        wildcard_resource = any(r == "*" for r in resources)
        if wildcard_action or wildcard_resource:
            what = []
            if wildcard_action:
                what.append('Action "*"')
            if wildcard_resource:
                what.append('Resource "*"')
            findings.append(
                Finding(
                    detector="iam-least-privilege",
                    layer=Layer.CLOUD,
                    severity=Severity.HIGH,
                    title="IAM execution role violates least privilege",
                    description=(
                        f"The AgentCore execution role grants {' and '.join(what)} "
                        f"(statement '{stmt.get('Sid', '?')}'). A compromised or confused "
                        f"agent inherits these permissions — blast radius is the entire "
                        f"account."
                    ),
                    file=source,
                    evidence=json.dumps(stmt, separators=(",", ":")),
                    confidence=Confidence.DETERMINISTIC,
                    remediation=Remediation(
                        summary="Scope Action and Resource to exactly the APIs and ARNs the agent needs.",
                        before='"Action": "*", "Resource": "*"',
                        after='"Action": ["bedrock:InvokeModel"], "Resource": "arn:aws:bedrock:...:foundation-model/..."',
                    ),
                    fingerprint=f"iam-least-privilege:{source}:{stmt.get('Sid', '?')}",
                )
            )
    return findings


def _guardrail_findings(cfg: dict, source: str) -> list[Finding]:
    g = cfg.get("bedrock_guardrails") or {}
    attached = bool(g.get("attached")) and bool(g.get("guardrail_id"))
    if attached:
        return []
    return [
        Finding(
            detector="guardrails-attached",
            layer=Layer.CLOUD,
            severity=Severity.HIGH,
            title="Bedrock Guardrails not attached",
            description=(
                "No active Bedrock Guardrail is attached to the model. Content and "
                "denied-topic policies are not enforced at the platform layer, so the "
                "agent's only defense is its system prompt."
            ),
            file=source,
            evidence=json.dumps(g, separators=(",", ":")),
            confidence=Confidence.DETERMINISTIC,
            remediation=Remediation(
                summary="Create a Guardrail and attach it to the AgentCore runtime.",
                before='"bedrock_guardrails": {"attached": false}',
                after='"bedrock_guardrails": {"guardrail_id": "gr-...", "attached": true}',
            ),
            fingerprint=f"guardrails-attached:{source}",
        )
    ]


def _memory_findings(cfg: dict, source: str) -> list[Finding]:
    m = cfg.get("agentcore_memory") or {}
    if not m.get("enabled"):
        return []
    problems = []
    if not m.get("encryption_at_rest"):
        problems.append("no encryption at rest")
    if not m.get("ttl_days"):
        problems.append("no TTL")
    if not problems:
        return []
    return [
        Finding(
            detector="memory-encryption-ttl",
            layer=Layer.CLOUD,
            severity=Severity.MEDIUM,
            title="AgentCore Memory retains sensitive data unsafely",
            description=(
                f"AgentCore Memory is enabled but has { ' and '.join(problems) }. "
                f"Conversation memory can hold PII indefinitely and unencrypted."
            ),
            file=source,
            evidence=json.dumps(m, separators=(",", ":")),
            confidence=Confidence.DETERMINISTIC,
            remediation=Remediation(
                summary="Enable KMS encryption at rest and set a retention TTL on the memory store.",
                before='"encryption_at_rest": false, "ttl_days": null',
                after='"encryption_at_rest": true, "ttl_days": 30',
            ),
            fingerprint=f"memory-encryption-ttl:{source}",
        )
    ]


def analyze_config(cfg: dict, source: str) -> list[Finding]:
    findings: list[Finding] = []
    role = cfg.get("execution_role") or {}
    if role.get("policy"):
        findings += policy_findings(role["policy"], source)
    findings += _guardrail_findings(cfg, source)
    findings += _memory_findings(cfg, source)
    return findings


# ---------------------------------------------------------------------------
# Live mode — read-only boto3
# ---------------------------------------------------------------------------
def check_live_role(
    role_name: str, region: str | None = None, iam_client=None
) -> tuple[list[Finding], dict]:
    """Fetch a real IAM role's policies (read-only) and analyze them.

    Returns ``(findings, raw)`` where ``raw`` holds the verbatim boto3 responses
    so a human can verify the verdict against the API, not the tool's summary.
    Only ``List*``/``Get*`` calls are issued — never a mutating API (charter
    rule 5). ``iam_client`` may be injected (a real client, or a botocore
    Stubber-backed client in the labeled demo).
    """
    if iam_client is not None:
        iam = iam_client
    else:
        import boto3  # imported lazily so offline runs never require credentials

        iam = boto3.client("iam", region_name=region)
    raw: dict[str, Any] = {}
    findings: list[Finding] = []
    src = f"iam-role://{role_name}"

    inline = iam.list_role_policies(RoleName=role_name)
    raw["list_role_policies"] = inline
    for pname in inline.get("PolicyNames", []):
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
        raw[f"get_role_policy:{pname}"] = doc
        findings += policy_findings(doc["PolicyDocument"], f"{src}#{pname}")

    attached = iam.list_attached_role_policies(RoleName=role_name)
    raw["list_attached_role_policies"] = attached
    for ap in attached.get("AttachedPolicies", []):
        pv = iam.get_policy(PolicyArn=ap["PolicyArn"])
        vid = pv["Policy"]["DefaultVersionId"]
        doc = iam.get_policy_version(PolicyArn=ap["PolicyArn"], VersionId=vid)
        raw[f"get_policy_version:{ap['PolicyName']}"] = doc
        findings += policy_findings(doc["PolicyVersion"]["Document"], f"{src}#{ap['PolicyName']}")

    return findings, raw


# ---------------------------------------------------------------------------
# Layer entry point
# ---------------------------------------------------------------------------
def _discover_config(agent_path: str) -> Path | None:
    p = Path(agent_path)
    candidate = p.with_suffix(".deploy.json")
    return candidate if candidate.exists() else None


def run(
    agent_path: str,
    deploy_config: str | None = None,
    live_role: str | None = None,
    region: str | None = None,
    raw_out: str | None = None,
) -> LayerReport:
    if live_role:
        try:
            findings, raw = check_live_role(live_role, region)
            if raw_out:
                Path(raw_out).write_text(json.dumps(raw, indent=2, default=str))
            detail = f"live IAM role '{live_role}'"
            if raw_out:
                detail += f"; raw responses written to {raw_out} for human verification"
            return LayerReport(Layer.CLOUD, "ran", detail, findings)
        except Exception as e:  # missing creds / role — degrade honestly
            return LayerReport(
                Layer.CLOUD, "skipped", f"live check unavailable: {type(e).__name__}: {e}", []
            )

    cfg_path = Path(deploy_config) if deploy_config else _discover_config(agent_path)
    if not cfg_path or not cfg_path.exists():
        return LayerReport(
            Layer.CLOUD,
            "skipped",
            "no deploy config found (pass --deploy-config or add <agent>.deploy.json)",
            [],
        )
    cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    src = str(cfg_path).replace("\\", "/")
    return LayerReport(Layer.CLOUD, "ran", f"offline analysis of {src}", analyze_config(cfg, src))
