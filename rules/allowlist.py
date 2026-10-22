"""Allowlist (C10): accepted risks with mandatory reason + expiry. Suppressed findings stay visible."""
from __future__ import annotations
import datetime as dt
import fnmatch
import os

HEADER = ("# vulnscan allowlist. Each entry needs rule_id, subject (fnmatch glob allowed), reason, expires.\n"
          "# Optional: sha256 (must match the finding's sha256 attribute when the rule provides one).\n"
          "# Expired entries stop suppressing. This file is rewritten by the dashboard; keep comments elsewhere.\n")


def load_allowlist(path: str | None, today: dt.date) -> dict:
    out = {"active": [], "expired": [], "invalid": []}
    if not path or not os.path.exists(path):
        return out
    import yaml
    with open(path, encoding="utf-8") as f:
        items = yaml.safe_load(f) or []
    if not isinstance(items, list):
        out["invalid"].append({"entry": items, "problem": "top level must be a list"})
        return out
    for e in items:
        if not isinstance(e, dict) or not all(e.get(k) for k in ("rule_id", "subject", "reason", "expires")):
            out["invalid"].append({"entry": e, "problem": "needs rule_id, subject, reason and expires"})
            continue
        try:
            exp = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        except ValueError:
            out["invalid"].append({"entry": e, "problem": "expires must be YYYY-MM-DD"})
            continue
        (out["expired"] if exp < today else out["active"]).append({**e, "expires": exp.isoformat()})
    return out


def apply_allowlist(findings: list, active: list) -> int:
    n = 0
    for f in findings:
        for e in active:
            if e["rule_id"] != f.rule_id or not fnmatch.fnmatch(f.subject, str(e["subject"])):
                continue
            if e.get("sha256") and f.attrs.get("sha256") != e["sha256"]:
                continue
            f.suppressed, f.suppression = True, {"reason": e["reason"], "expires": e["expires"]}
            n += 1
            break
    return n


def append_entry(path: str, entry: dict):
    import yaml
    items = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            items = yaml.safe_load(f) or []
    items.append({k: (str(v) if k == "expires" else v) for k, v in entry.items()})
    with open(path, "w", encoding="utf-8") as f:
        f.write(HEADER)
        yaml.safe_dump(items, f, sort_keys=False)
