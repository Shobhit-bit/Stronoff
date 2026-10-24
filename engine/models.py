from __future__ import annotations
from dataclasses import dataclass, field, asdict

SEV_SCORE = {"critical": 90, "high": 70, "medium": 40, "low": 15, "info": 0}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}
CATEGORIES = {"weakness", "ioc", "exposure", "hygiene", "info"}


@dataclass
class Finding:
    rule_id: str
    rule_version: int
    title: str
    severity: str
    confidence: str
    category: str
    subject: str
    evidence: list = field(default_factory=list)
    evidence_total: int = 0
    why: str = ""
    fix: str = ""
    features: dict = field(default_factory=dict)
    attrs: dict = field(default_factory=dict)       # subject attributes used by the allowlist (e.g. sha256)
    status: str = "fail"
    suppressed: bool = False
    suppression: dict | None = None
    scan_timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuleResult:
    rule_id: str
    title: str
    outcome: str                    # pass | fail | unknown | na | error
    reason: str = ""
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    suppressed_count: int = 0

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "title": self.title, "outcome": self.outcome, "reason": self.reason,
                "finding_count": sum(not f.suppressed for f in self.findings),
                "suppressed_count": self.suppressed_count, "notes": self.notes}
