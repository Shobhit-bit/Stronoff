"""python -m ml {ingest,analyze,run,synth} [--output output] [--db output/history.db]"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import MIN_SNAPSHOTS, MIN_Z_SNAPSHOTS
from .anomaly import analyze
from .drift import compute_drift
from .history import History
from .snapshot import build_snapshot, NotOneScan


def cmd_ingest(a) -> int:
    try:
        snap = build_snapshot(a.output, force=a.force)
    except NotOneScan as e:
        print(f"not ingested: {e}", file=sys.stderr)
        return 1
    h = History(a.db)
    sid, created = h.ingest(snap)
    h.close()
    measured = sum(v is not None for v in snap["features"].values())
    print(f"{'ingested' if created else 'already stored'}: snapshot {sid} ({snap['scan_timestamp']}, host {snap['host']}), "
          f"{measured}/{len(snap['features'])} features, {len(snap['maps'])} comparison maps"
          + (f", collectors missing: {snap['collectors_missing']}" if snap["collectors_missing"] else ""))
    return 0


def build_report(db: str, host: str | None = None, **kw) -> dict | None:
    h = History(db)
    host = host or h.latest_host()
    if host is None:
        h.close()
        return None
    snaps = h.snapshots(host)
    h.close()
    rep = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "host": host, "snapshots": len(snaps),
           "latest": snaps[-1]["scan_timestamp"],
           "drift": compute_drift(snaps[-2], snaps[-1]) if len(snaps) >= 2 else None,
           "anomaly": analyze(snaps, **kw),
           "history": [{"id": s["id"], "scan_timestamp": s["scan_timestamp"],
                        "features_measured": sum(v is not None for v in s["features"].values()),
                        "root_collectors": sum(s["ran_as_root"].values()), "collectors": len(s["ran_as_root"]),
                        "spread_minutes": s["scan_spread_minutes"]} for s in snaps[-100:]]}
    return rep


def print_report(rep: dict):
    print(f"Host {rep['host']}: {rep['snapshots']} scan(s) stored.")
    d = rep["drift"]
    if d is None:
        print("Drift: needs 2 scans.")
    else:
        c = d["counts"]
        print(f"Drift {d['previous'][:16]} -> {d['current'][:16]}: high {c['high']} medium {c['medium']} low {c['low']} info {c['info']}"
              f" ({len(d['compared_maps'])} maps compared, {len(d['skipped_maps'])} skipped)")
        for e in [e for e in d["events"] if e["severity"] in ("high", "medium")][:15]:
            print(f"  {e['severity'].upper():6} {e['map']:18} {e['change']:8} {e['key'][:70]}")
    an = rep["anomaly"]
    print(f"Anomaly detection: {an['status']}" + (f" - {an['message']}" if an.get("message") else ""))
    l = an.get("latest")
    if l:
        print(f"  latest: {'ANOMALOUS' if l['anomalous'] else 'normal'}  max|z| {l['max_abs_z']}  coverage {l['feature_coverage']:.0%}"
              + (f"  forest rank {l['iforest_rank']}" if l.get("iforest_rank") is not None else ""))
        for r in l["reasons"]:
            print(f"    - {r}")
        for t in l["top_deviations"][:5]:
            print(f"    {t['feature']:26} {t['value']:g} (typical {t['typical']:g}, z {t['z']:+.1f})")


def cmd_analyze(a) -> int:
    rep = build_report(a.db, a.host, min_snapshots=a.min_snapshots)
    if rep is None:
        print("history is empty: run `python -m ml ingest` first", file=sys.stderr)
        return 1
    Path(a.report or Path(a.output) / "ml_report.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    print_report(rep)
    return 0


def cmd_synth(a) -> int:
    from .synthetic import benchmark
    r = benchmark(trials=a.trials)
    print(f"Synthetic benchmark ({a.trials} trials, 45-scan history). Flag rate per scenario:")
    for k, v in r.items():
        print(f"  {k:48s} {v:5.0%}")
    print("This validates mechanics only; real false-positive rates need your own scan history.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="ml", description="vulnscan Phase 4: history, drift, anomaly detection")
    ap.add_argument("command", choices=["ingest", "analyze", "run", "synth"])
    ap.add_argument("--output", default="output")
    ap.add_argument("--db", help="history database (default: <output>/history.db)")
    ap.add_argument("--host")
    ap.add_argument("--report")
    ap.add_argument("--force", action="store_true", help="ingest even if collector outputs are far apart in time")
    ap.add_argument("--min-snapshots", type=int, default=MIN_SNAPSHOTS)
    ap.add_argument("--trials", type=int, default=20)
    a = ap.parse_args()
    a.db = a.db or str(Path(a.output) / "history.db")
    if a.command == "ingest":
        return cmd_ingest(a)
    if a.command == "analyze":
        return cmd_analyze(a)
    if a.command == "synth":
        return cmd_synth(a)
    rc = cmd_ingest(a)
    return cmd_analyze(a) if rc == 0 else rc


if __name__ == "__main__":
    sys.exit(main())
