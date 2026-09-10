"""Dashboard backend — every number it serves comes from a real scan.

There is no mock data path in this module. When something has not been run yet,
the API returns an explicit empty state (``"state": "empty"``) with a reason,
so the UI can say "not run yet" instead of showing invented numbers. When a
capability is unavailable (e.g. AWS permissions), the API returns
``"state": "unavailable"`` plus the real error text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentaudit.audit import run_audit
from agentaudit.discovery import list_registered_agents, summarize
from agentaudit.layers.capability_graph import analyze_capability_pairs
from agentaudit.remediation.deploy import POLICY_DIR, remediate_findings

STATE_FILE = Path("out/dashboard_state.json")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ScanRecord:
    """One completed audit of one agent — all real output."""

    target: str
    grade: str
    score: int
    duration_ms: int
    generated_at: str
    counts: dict
    findings: list[dict]
    layers: list[dict]
    policies: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "grade": self.grade,
            "score": self.score,
            "duration_ms": self.duration_ms,
            "generated_at": self.generated_at,
            "counts": self.counts,
            "findings": self.findings,
            "layers": self.layers,
            "policies": self.policies,
        }


class DashboardState:
    """Persisted dashboard state. Starts genuinely empty."""

    def __init__(self, state_file: Path | str = STATE_FILE):
        self.state_file = Path(state_file)
        self.scans: dict[str, dict] = {}
        self.last_verified: str | None = None
        self._load()

    def _load(self) -> None:
        if self.state_file.exists():
            try:
                d = json.loads(self.state_file.read_text(encoding="utf-8"))
                self.scans = d.get("scans", {})
                self.last_verified = d.get("last_verified")
            except Exception:
                self.scans, self.last_verified = {}, None

    def save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(
            json.dumps({"scans": self.scans, "last_verified": self.last_verified}, indent=2),
            encoding="utf-8",
        )

    def clear(self) -> None:
        self.scans, self.last_verified = {}, None
        if self.state_file.exists():
            self.state_file.unlink()

    # --- real work -------------------------------------------------------
    def run_scan(self, target: str, remediate: bool = True,
                 dry_run: bool = True, gateway_arn: str = "",
                 gateway_id: str = "") -> dict:
        """Run the real 3-stage pipeline against one agent file."""
        card = run_audit(target)

        # Stage 1 also contributes the capability-pair (trust graph) findings
        # that Cedar remediation is generated from.
        cap = analyze_capability_pairs(target)
        all_findings = list(card.findings) + cap

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            counts[f.severity.value] += 1

        policies: list[dict] = []
        if remediate and cap:
            results = remediate_findings(
                cap,
                gateway_arn=gateway_arn or "<gateway-not-provisioned>",
                gateway_id=gateway_id or "pending",
                dry_run=dry_run,
            )
            policies = [r.to_dict() for r in results]

        rec = ScanRecord(
            target=target,
            grade=card.grade,
            score=card.score,
            duration_ms=card.duration_ms,
            generated_at=_now(),
            counts=counts,
            findings=[f.to_dict() for f in all_findings],
            layers=[
                {"layer": lr.layer.value, "status": lr.status, "detail": lr.detail}
                for lr in card.layer_reports
            ],
            policies=policies,
        )
        self.scans[target] = rec.to_dict()
        self.last_verified = rec.generated_at
        self.save()
        return rec.to_dict()

    def run_remote_scan(self, url: str) -> dict:
        """Scan a public GitHub repo (Layer 2 static only) and store the result.

        All validation, shallow-clone, resource limits, isolation, single-flight
        and cleanup live in :mod:`agentaudit.dashboard.remote_scan`. This method
        only persists the returned record under its synthetic target key so the
        existing dashboard views render it unchanged.
        """
        from agentaudit.dashboard.remote_scan import scan_remote_repo

        record = scan_remote_repo(url)
        self.scans[record["target"]] = record
        self.last_verified = record["generated_at"]
        self.save()
        return record

    def run_org_scan(self, targets: list[str] | None = None) -> dict:
        """Scan every discovered agent (or an explicit target list)."""
        disc = list_registered_agents()
        if targets is None:
            # Discovery returns deployed runtimes; we can only statically scan
            # local source files, so surface discovery separately from scans.
            targets = []
        for t in targets:
            self.run_scan(t)
        return {
            "discovery": disc.to_dict(),
            "scanned": targets,
            "summary": self.org_summary(),
        }

    # --- views -----------------------------------------------------------
    def org_summary(self) -> dict:
        if not self.scans:
            return {"state": "empty", "reason": "no scans have been run yet",
                    "totals": {}, "per_agent": {}, "agent_count": 0,
                    "total_findings": 0}

        per_agent = {t: s["findings"] for t, s in self.scans.items()}
        totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        per_counts = {}
        for t, findings in per_agent.items():
            c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                if f["severity"] in c:
                    c[f["severity"]] += 1
            per_counts[t] = c
            for k, v in c.items():
                totals[k] += v
        return {
            "state": "live",
            "totals": totals,
            "per_agent": per_counts,
            "agent_count": len(per_agent),
            "total_findings": sum(totals.values()),
            "last_verified": self.last_verified,
        }

    def policies_view(self, policy_dir: Path | str = POLICY_DIR) -> dict:
        """Every Cedar policy on disk, with its deployment result."""
        d = Path(policy_dir)
        if not d.exists():
            return {"state": "empty", "reason": "no policies generated yet",
                    "policies": []}
        items = []
        for cedar in sorted(d.glob("*.cedar")):
            meta_path = cedar.with_suffix(".json")
            meta: dict[str, Any] = {}
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
            items.append({
                "id": cedar.stem,
                "file": str(cedar).replace("\\", "/"),
                "cedar": cedar.read_text(encoding="utf-8"),
                "status": meta.get("status", "unknown"),
                "dry_run": meta.get("dry_run", True),
                "policy_name": meta.get("policy_name", cedar.stem),
                "policy_id": meta.get("policy_id"),
                "policy_arn": meta.get("policy_arn"),
                "error": meta.get("error"),
                "timestamp": meta.get("timestamp"),
            })
        if not items:
            return {"state": "empty", "reason": "no policies generated yet",
                    "policies": []}
        return {"state": "live", "policies": items, "count": len(items)}

    def agents_view(self) -> dict:
        d = list_registered_agents().to_dict()
        if not d["available"]:
            d["state"] = "unavailable"
        elif d["count"] == 0:
            d["state"] = "empty"
        else:
            d["state"] = "live"
        return d

    def snapshot(self) -> dict:
        return {
            "state": "live" if self.scans else "empty",
            "last_verified": self.last_verified,
            "scans": self.scans,
            "org": self.org_summary(),
            "policies": self.policies_view(),
            "agents": self.agents_view(),
            "server_time": _now(),
        }
