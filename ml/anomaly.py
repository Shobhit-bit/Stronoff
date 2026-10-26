"""Anomaly detection over scan history (scikit-learn IsolationForest + robust per-feature z-scores).

Why TWO detectors:
  * IsolationForest finds scans that are unusual as a COMBINATION of features. It is blind to a feature
    that never varied in training (a tree cannot split a constant), which is exactly 'a new SUID file
    appeared'. So it is not enough alone.
  * Robust z-scores (median / MAD, with a floor on natural noise) catch big single-feature jumps and
    explain WHICH features moved. They need little history (MIN_Z_SNAPSHOTS).

Honesty constraints:
  * Below MIN_SNAPSHOTS the forest is not trained at all and no model score is reported.
  * Missing features (a collector that did not run) are imputed with the median and counted; a scan with
    too few measured features is reported as 'insufficient data', never as normal or anomalous.
  * The latest scan is scored by a model that did NOT see it.
"""
from __future__ import annotations
import warnings

import numpy as np
from sklearn.ensemble import IsolationForest

from . import MIN_SNAPSHOTS, MIN_Z_SNAPSHOTS
from .features import FEATURES, FEATURE_NAMES, VOLATILE_MASK

DEFAULTS = dict(flag_percentile=99.0, z_structural=3.0, z_volatile=6.0, min_latest_coverage=0.6, max_history=180,
                n_estimators=100, seed=0, timeline_n=60, use_iforest=True)


def to_matrix(snaps: list[dict]) -> np.ndarray:
    return np.array([[(s["features"].get(n) if s["features"].get(n) is not None else np.nan) for n in FEATURE_NAMES]
                     for s in snaps], dtype=float)


def _stats(train: np.ndarray):
    """Median and noise scale per feature from history (NaN-aware)."""
    with np.errstate(all="ignore"), warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)            # features never measured -> all-NaN column, handled below
        med = np.nanmedian(train, axis=0)
        mad = np.nanmedian(np.abs(train - med), axis=0) * 1.4826
    abs_f = np.array([f.abs_floor for f in FEATURES])
    rel_f = np.array([f.rel_floor for f in FEATURES])
    scale = np.maximum.reduce([np.nan_to_num(mad), abs_f, rel_f * np.abs(np.nan_to_num(med))])
    return med, scale


def analyze(snaps: list[dict], min_snapshots: int = MIN_SNAPSHOTS, min_z: int = MIN_Z_SNAPSHOTS, **kw) -> dict:
    p = {**DEFAULTS, **kw}
    snaps = snaps[-p["max_history"]:]
    n = len(snaps)
    out = {"snapshots": n, "min_snapshots_for_model": min_snapshots, "min_snapshots_for_deviations": min_z + 1,
           "model_ready": False, "latest": None, "timeline": []}
    if n < min_z + 1:
        out["status"] = "learning"
        out["message"] = (f"{n} scan(s) stored. Per-feature deviation checks start at {min_z + 1} scans and the "
                          f"IsolationForest at {min_snapshots}. Drift detection works from 2 scans.")
        return out

    X = to_matrix(snaps)
    train, latest = X[:-1], X[-1].copy()
    usable = np.isnan(train).mean(axis=0) <= 0.5                    # features measured in >= half of the history
    med, scale = _stats(train)
    measured = ~np.isnan(latest) & usable
    coverage = float(measured.sum() / max(usable.sum(), 1))
    imputed = [FEATURE_NAMES[i] for i in range(len(latest)) if usable[i] and np.isnan(latest[i])]
    lat = np.where(np.isnan(latest), med, latest)
    z = np.where(usable, (lat - np.nan_to_num(med)) / scale, 0.0)

    thr_vec = np.where(np.array(VOLATILE_MASK), p["z_volatile"], p["z_structural"])
    max_z = float(np.max(np.abs(z))) if usable.any() else 0.0
    flagged = [i for i in range(len(z)) if usable[i] and abs(z[i]) >= thr_vec[i]]

    top = [{"feature": FEATURE_NAMES[i], "group": FEATURES[i].group, "value": float(lat[i]),
            "typical": float(med[i]), "z": float(z[i]), "flag_at": float(thr_vec[i]), "flagged": bool(i in flagged)}
           for i in np.argsort(-np.abs(z))[:8] if abs(z[i]) >= 2.0]

    res = {"scan_timestamp": snaps[-1]["scan_timestamp"], "feature_coverage": round(coverage, 3),
           "imputed_features": imputed, "max_abs_z": round(max_z, 2), "top_deviations": top,
           "iforest_score": None, "iforest_threshold": None, "iforest_rank": None,
           "anomalous": False, "level": "normal", "reasons": []}

    if coverage < p["min_latest_coverage"]:
        out["status"] = "insufficient_data_latest"
        res["reasons"] = [f"only {coverage:.0%} of the features could be measured in the latest scan "
                          "(collector missing or not run as root); not judged"]
        out["latest"] = res
        return out

    if flagged:
        res["anomalous"], res["level"] = True, "alert"          # a concrete feature left its normal range
        res["flagged_features"] = [FEATURE_NAMES[i] for i in flagged]
        res["reasons"].append("beyond normal variation for: " + ", ".join(FEATURE_NAMES[i] for i in flagged[:6]))

    if n >= min_snapshots and p["use_iforest"]:
        cols = np.where(usable)[0]
        tr = np.where(np.isnan(train), med, train)
        Xs = np.clip((tr[:, cols] - med[cols]) / scale[cols], -20, 20)
        xl = np.clip((lat[cols] - med[cols]) / scale[cols], -20, 20)[None, :]
        iso = IsolationForest(n_estimators=p["n_estimators"], max_samples=min(256, len(Xs)),
                              contamination="auto", random_state=p["seed"]).fit(Xs)
        tr_scores = -iso.score_samples(Xs)
        s_latest = float(-iso.score_samples(xl)[0])
        thr = float(np.percentile(tr_scores, p["flag_percentile"]))
        res.update(iforest_score=round(s_latest, 4), iforest_threshold=round(thr, 4),
                   iforest_rank=round(float((tr_scores < s_latest).mean()), 3))
        if s_latest > thr:
            res["anomalous"] = True
            if res["level"] != "alert":
                res["level"] = "notice"                         # forest only: low confidence, review manually
            res["reasons"].append("unusual combination of features compared with previous scans (IsolationForest; low confidence on its own)")
        out["model_ready"] = True
        # in-sample timeline (for the chart only; the verdict above is out-of-sample)
        alln = np.where(np.isnan(X), med, X)
        Xa = np.clip((alln[:, cols] - med[cols]) / scale[cols], -20, 20)
        iso2 = IsolationForest(n_estimators=p["n_estimators"], max_samples=min(256, len(Xa)),
                               contamination="auto", random_state=p["seed"]).fit(Xa)
        sc = -iso2.score_samples(Xa)
        mz = np.max(np.abs((alln - np.nan_to_num(med)) / scale)[:, usable], axis=1)
        k = p["timeline_n"]
        out["timeline"] = [{"scan_timestamp": snaps[i]["scan_timestamp"], "iforest_score": round(float(sc[i]), 4),
                            "max_abs_z": round(float(mz[i]), 2)} for i in range(max(0, n - k), n)]

    out["status"] = "ready" if out["model_ready"] else "deviations_only"
    out["message"] = ("" if out["model_ready"] else
                      f"Deviation checks active; the IsolationForest starts at {min_snapshots} scans ({n} stored).")
    out["latest"] = res
    return out
