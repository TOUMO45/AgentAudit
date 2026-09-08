"""Shared data model for AgentAudit findings and scorecards.

Every layer emits :class:`Finding` objects; the scorer dedups and weights them
into a :class:`Scorecard`, which the reporters render. Keeping one vocabulary
here is what lets three independent layers produce a single unified report.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Layer(str, enum.Enum):
    """The three independent audit layers."""

    BEHAVIORAL = "behavioral"
    ARCHITECTURAL = "architectural"
    CLOUD = "cloud"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            "critical": 40,
            "high": 20,
            "medium": 10,
            "low": 3,
            "info": 0,
        }[self.value]

    @property
    def rank(self) -> int:
        """Higher = more severe. Used for ordering."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Confidence(str, enum.Enum):
    """How the finding was decided. Deterministic checks are trusted first
    (charter rule 2)."""

    DETERMINISTIC = "deterministic"
    HEURISTIC = "heuristic"
    LLM_JUDGED = "llm-judged"


@dataclass
class Remediation:
    """A concrete, diff-ready fix — not just a warning (charter product promise)."""

    summary: str
    before: str = ""
    after: str = ""

    def as_diff(self) -> str:
        if not (self.before or self.after):
            return ""
        lines = ["--- before", "+++ after"]
        for ln in self.before.splitlines():
            lines.append(f"- {ln}")
        for ln in self.after.splitlines():
            lines.append(f"+ {ln}")
        return "\n".join(lines)


@dataclass
class Finding:
    """A single audit finding from any layer."""

    detector: str  # stable id, e.g. "idor-in-agent"
    layer: Layer
    severity: Severity
    title: str
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    remediation: Remediation | None = None
    confidence: Confidence = Confidence.DETERMINISTIC
    # Stable identity for dedup across layers. Defaults to detector+file+line.
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = f"{self.detector}:{self.file}:{self.line}"

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or "(no location)"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["location"] = self.location
        if self.remediation is not None:
            d["remediation"] = asdict(self.remediation)
            d["remediation"]["diff"] = self.remediation.as_diff()
        return d


@dataclass
class LayerReport:
    """Per-layer status so a skipped layer (e.g. no AWS creds) is explicit,
    never silently dropped."""

    layer: Layer
    status: str  # "ran" | "skipped" | "error"
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Scorecard:
    """The unified, signable result of a full audit."""

    agent_path: str
    generated_at: str
    findings: list[Finding]
    layer_reports: list[LayerReport]
    score: int = 0  # 0 (clean) .. 100 (worst); higher = more risk
    grade: str = "A"
    tool_version: str = "0.1.0"
    duration_ms: int = 0
    signature: str | None = None

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def counts_by_layer(self) -> dict[str, int]:
        out = {l.value: 0 for l in Layer}
        for f in self.findings:
            out[f.layer.value] += 1
        return out

    def layers_with_findings(self) -> int:
        return sum(1 for c in self.counts_by_layer().values() if c > 0)

    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": "agentaudit",
            "tool_version": self.tool_version,
            "agent_path": self.agent_path,
            "generated_at": self.generated_at,
            "score": self.score,
            "grade": self.grade,
            "duration_ms": self.duration_ms,
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_layer": self.counts_by_layer(),
            "layer_reports": [
                {"layer": lr.layer.value, "status": lr.status, "detail": lr.detail}
                for lr in self.layer_reports
            ],
            "findings": [f.to_dict() for f in self.findings],
        }
        if include_signature and self.signature is not None:
            d["signature"] = self.signature
        return d
