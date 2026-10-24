"""python -m engine [--output output] [--out output/findings.json] ..."""
import argparse
import json
import sys
from pathlib import Path

import rules  # noqa: F401  (registers every rule)
from .runner import run_all

ICON = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}


def main():
    ap = argparse.ArgumentParser(description="vulnscan rule engine")
    ap.add_argument("--output", default="output", help="folder with collector JSON")
    ap.add_argument("--out", help="findings file (default: <output>/findings.json)")
    ap.add_argument("--thresholds", default="thresholds.yaml")
    ap.add_argument("--allowlist", default="allowlist.yaml")
    ap.add_argument("--min-severity", default="info", choices=list(ICON))
    a = ap.parse_args()

    report = run_all(a.output, a.thresholds, a.allowlist)
    out = Path(a.out or Path(a.output) / "findings.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    c = report["coverage"]
    print(f"Coverage: {c['evaluated']}/{c['rules_total']} rules evaluated | "
          f"pass {c['pass']} fail {c['fail']} | UNKNOWN {c['unknown']} | N/A {c['na']} | errors {c['error']}")
    for u in c["unknown_reasons"]:
        print(f"  ? {u['rule_id']}: {u['reason']}")
    order = list(ICON)
    shown = [f for f in report["findings"] if order.index(f["severity"]) <= order.index(a.min_severity)]  # order is most-severe first
    print(f"\n{len(shown)} finding(s):")
    for f in shown:
        tag = " [suppressed]" if f["suppressed"] else ""
        print(f"  {ICON[f['severity']]} {f['rule_id']:8} {f['confidence'][:1].upper()} {f['subject'][:70]}{tag}")
    print(f"\nWrote {out}")
    sys.exit(0)


if __name__ == "__main__":
    main()
