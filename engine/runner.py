"""Evaluate rules against loaded collector data and build the findings report."""
from __future__ import annotations
import datetime as dt
from pathlib import Path

from . import ENGINE_VERSION
from .allowlist import load_allowlist, apply_allowlist
from .config import load_thresholds
from .core import REGISTRY, Ctx, Unknown, NotApplicable, dig, RuleMeta
from .loader import load_all
from .models import RuleResult, SEV_SCORE, CONF_RANK


def _merge(findings: list) -> list:
    """One finding per (rule_id, subject) (C5): merge evidence, keep the highest severity."""
    by: dict = {}
    for f in findings:
        k = (f.rule_id, f.subject)
        if k not in by:
            by[k] = f
            continue
        g = by[k]
        g.evidence_total += f.evidence_total
        g.evidence = (g.evidence + f.evidence)[:10]
        if SEV_SCORE[f.severity] > SEV_SCORE[g.severity]:
            g.severity, g.why, g.fix = f.severity, f.why, f.fix
            g.features["severity_score"] = SEV_SCORE[f.severity]
        g.features["network_exposed"] |= f.features["network_exposed"]
        g.features["runs_as_root"] |= f.features["runs_as_root"]
    return list(by.values())


def evaluate(meta: RuleMeta, loaded: dict, thresholds: dict, scan_ts: str = "") -> RuleResult:
    res = RuleResult(meta.id, meta.title, "pass")

    def done(outcome, reason=""):
        res.outcome, res.reason = outcome, reason
        return res

    if meta.applies_to == "arch":
        pk = loaded.get("packages")
        if pk and pk.usable and pk.data.get("pacman_available") is False:
            return done("na", "not an Arch/pacman system")

    for name, fields in meta.requires.items():
        l = loaded.get(name)
        if l is None or not l.usable:
            return done("unknown", l.reason if l else f"{name} not loaded")
        if name in meta.needs_root and not l.ran_as_root:
            return done("unknown", f"{name} collector ran without root (needs root for this rule)")
        for path in fields:
            if dig(l.data, path) is None:
                hint = f" ({l.first_warning})" if l.first_warning else ""
                return done("unknown", f"{name}.{path} not collected{hint}")

    ctx = Ctx(loaded, thresholds, meta)
    try:
        meta.fn(ctx)
    except Unknown as e:
        res.notes = ctx.notes
        return done("unknown", str(e))
    except NotApplicable as e:
        return done("na", str(e))
    except Exception as e:            # a buggy rule must never take the engine down
        return done("error", f"{type(e).__name__}: {e}")

    res.notes = ctx.notes
    findings = _merge(ctx._findings)
    for f in findings:
        f.scan_timestamp = scan_ts
    res.findings = findings
    if not findings and ctx.partial_reasons:
        return done("unknown", "; ".join(ctx.partial_reasons))
    return done("fail" if findings else "pass")


def _rank_key(f):
    expo = int(f.features.get("network_exposed", False)) + int(f.features.get("runs_as_root", False))
    return (-SEV_SCORE[f.severity], -CONF_RANK[f.confidence], -expo, f.rule_id, f.subject)


def run_all(out_dir, thresholds_path=None, allowlist_path=None, today: dt.date | None = None) -> dict:
    out_dir = Path(out_dir)
    thresholds = load_thresholds(thresholds_path)
    loaded = load_all(out_dir)
    today = today or dt.date.today()
    stamps = [l.env.get("timestamp", "") for l in loaded.values() if l.env]
    scan_ts = max(stamps) if stamps else ""
    allow = load_allowlist(allowlist_path, today)

    results, all_findings = [], []
    for rid in sorted(REGISTRY):
        r = evaluate(REGISTRY[rid], loaded, thresholds, scan_ts)
        n = apply_allowlist(r.findings, allow["active"])
        r.suppressed_count = n
        if r.outcome == "fail" and all(f.suppressed for f in r.findings):
            r.outcome = "pass"
        results.append(r)
        all_findings += r.findings

    all_findings.sort(key=_rank_key)
    counts = {k: sum(r.outcome == k for r in results) for k in ("pass", "fail", "unknown", "na", "error")}
    evaluated = counts["pass"] + counts["fail"]
    return {
        "schema_version": "1.0",
        "engine_version": ENGINE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scan_timestamp": scan_ts,
        "coverage": {
            "rules_total": len(results), "evaluated": evaluated, **counts,
            "unknown_reasons": [{"rule_id": r.rule_id, "reason": r.reason}
                                for r in results if r.outcome in ("unknown", "error")],
            "collectors": {n: {"status": l.status, "reason": l.reason,
                               "ran_as_root": l.ran_as_root if l.env else None} for n, l in loaded.items()},
        },
        "allowlist": {"applied": sum(r.suppressed_count for r in results),
                      "expired": allow["expired"], "invalid": allow["invalid"]},
        "rules": [r.to_dict() for r in results],
        "findings": [f.to_dict() for f in all_findings],
    }
