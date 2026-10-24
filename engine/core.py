"""Rule registry, decorator and evaluation context."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable

from .models import Finding, SEV_SCORE, CONF_RANK, CATEGORIES

REGISTRY: dict[str, "RuleMeta"] = {}


class Unknown(Exception):
    """Raised by a rule when it cannot decide (missing/unreadable input). Never means PASS."""


class NotApplicable(Exception):
    pass


@dataclass
class RuleMeta:
    id: str
    title: str
    version: int
    category: str
    severity: str
    confidence: str
    applies_to: str
    requires: dict
    needs_root: tuple
    optional: tuple
    why: str
    fix: str
    fn: Callable = field(repr=False, default=None)


def rule(*, id, title, category, severity, confidence, why, fix, requires, version=1,
         applies_to="any", needs_root=(), optional=()):
    assert category in CATEGORIES, f"{id}: bad category {category}"
    assert severity in SEV_SCORE and confidence in CONF_RANK, f"{id}: bad severity/confidence"
    assert applies_to in ("any", "arch")

    def deco(fn):
        assert id not in REGISTRY, f"duplicate rule id {id} (IDs are never reused)"
        REGISTRY[id] = RuleMeta(id, title, version, category, severity, confidence, applies_to,
                                requires, tuple(needs_root), tuple(optional), why, fix, fn)
        return fn
    return deco


def dig(obj, path: str):
    """Nested get with dotted path; returns None if any level is missing."""
    for key in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
        if obj is None:
            return None
    return obj


def ev(collector: str, path: str, observed, expected="") -> dict:
    return {"collector": collector, "path": path, "observed": observed, "expected": expected}


MAX_EVIDENCE = 10


class Ctx:
    def __init__(self, loaded: dict, thresholds: dict, meta: RuleMeta):
        self._loaded, self.thresholds, self.meta = loaded, thresholds, meta
        self.notes: list[str] = []
        self.partial_reasons: list[str] = []
        self._findings: list[Finding] = []

    # ---- data access
    def has(self, name: str) -> bool:
        l = self._loaded.get(name)
        return bool(l and l.usable)

    def d(self, name: str) -> dict:
        if not self.has(name):
            raise Unknown(f"{name} data unavailable")
        return self._loaded[name].data

    def env(self, name: str) -> dict:
        return self._loaded[name].env

    def get(self, name: str, path: str, default=None):
        if not self.has(name):
            return default
        v = dig(self._loaded[name].data, path)
        return default if v is None else v

    def th(self, key: str):
        return self.thresholds[key]

    def note(self, msg: str):
        self.notes.append(msg)

    def partial(self, msg: str):
        """Coverage was incomplete. If the rule then finds nothing, it is UNKNOWN, not PASS."""
        self.partial_reasons.append(msg)
        self.notes.append(msg)

    # ---- findings
    def fail(self, subject: str, evidence=None, severity=None, confidence=None, why=None, fix=None,
             exposed=False, runs_as_root=False, attrs=None, total=None, title=None):
        m = self.meta
        evidence = list(evidence or [])
        sev = severity or m.severity
        conf = confidence or m.confidence
        f = Finding(
            rule_id=m.id, rule_version=m.version, title=title or m.title, severity=sev, confidence=conf,
            category=m.category, subject=str(subject), evidence=evidence[:MAX_EVIDENCE],
            evidence_total=total if total is not None else len(evidence),
            why=why or m.why, fix=fix or m.fix,
            features={"severity_score": SEV_SCORE[sev], "confidence_rank": CONF_RANK[conf],
                      "network_exposed": bool(exposed), "runs_as_root": bool(runs_as_root),
                      "category": m.category},
            attrs=attrs or {})
        self._findings.append(f)
        return f
