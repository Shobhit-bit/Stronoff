import copy
import numpy as np
import pytest

from engine.loader import Loaded, COLLECTORS
from ml import features, snapshot, drift, anomaly, synthetic
from ml.history import History
from tests.helpers import env


def _loaded(**datas):
    L = {n: Loaded.from_envelope(n, env(n, d)) for n, d in datas.items()}
    for n in COLLECTORS:
        L.setdefault(n, Loaded(n, "missing", "x"))
    return L


# ---------------- features ----------------
def test_missing_collector_gives_none_not_zero():
    v = features.extract(_loaded())
    assert all(x is None for x in v.values())


def test_feature_values():
    L = _loaded(accounts={"counts": {"total": 40, "human": 1, "with_login_shell": 2}, "integrity": {"uid0_accounts": ["root"]},
                          "users": [{"name": "a", "password": None}], "sessions": [], "privileged_group_members": {"wheel": ["a"]}},
                kernel={"sysctl": {"kernel.randomize_va_space": 0, "kernel.yama.ptrace_scope": 0}, "cpu_mitigations": {"a": "Vulnerable: x", "b": "Not affected"}})
    v = features.extract(L)
    assert v["acc_total"] == 40 and v["acc_uid0"] == 1 and v["acc_priv_group_members"] == 1
    assert v["acc_empty_password"] is None                       # no shadow data: unknown, not 0
    assert v["krn_aslr_off"] == 1 and v["krn_weak_sysctls"] >= 1 and v["krn_cpu_vulnerable"] == 1
    assert v["fs_suid"] is None


def test_broken_extractor_does_not_raise():
    assert features.extract(_loaded(accounts={"counts": "garbage"}))["acc_total"] is None


# ---------------- snapshot ----------------
def _write(tmp_path, spread_min=0):
    import json, datetime as dt
    base = dt.datetime(2026, 10, 21, 10, 0, tzinfo=dt.timezone.utc)
    for i, n in enumerate(COLLECTORS):
        e = env(n, {"counts": {"total": 1}} if n == "accounts" else {})
        e["timestamp"] = (base + dt.timedelta(minutes=spread_min * i / (len(COLLECTORS) - 1))).isoformat()
        (tmp_path / f"{n}.json").write_text(json.dumps(e))


def test_snapshot_ok_and_rejects_mixed_age_outputs(tmp_path):
    _write(tmp_path, 5)
    s = snapshot.build_snapshot(tmp_path)
    assert s["scan_spread_minutes"] == 5 and s["features"]["acc_total"] == 1.0
    _write(tmp_path, 300)
    with pytest.raises(snapshot.NotOneScan):
        snapshot.build_snapshot(tmp_path)
    assert snapshot.build_snapshot(tmp_path, force=True)


def test_snapshot_refuses_when_nothing_usable(tmp_path):
    with pytest.raises(snapshot.NotOneScan):
        snapshot.build_snapshot(tmp_path)


# ---------------- history ----------------
def test_history_dedupes(tmp_path):
    _write(tmp_path)
    s = snapshot.build_snapshot(tmp_path)
    h = History(tmp_path / "h.db")
    assert h.ingest(s)[1] is True and h.ingest(s)[1] is False and len(h.snapshots()) == 1


# ---------------- drift ----------------
def _snap(ts, maps, root=True):
    return {"scan_timestamp": ts, "maps": maps, "map_root": {k: root for k in maps}}


def test_drift_added_removed_changed_and_severity():
    a = _snap("t1", {"suid_sgid": {"/usr/bin/sudo": "h1"}, "listening": {"tcp/22": "sshd|loopback"}, "users": {"bob": "uid=1000"}})
    b = _snap("t2", {"suid_sgid": {"/usr/bin/sudo": "h2", "/tmp/x": "h3"}, "listening": {"tcp/22": "sshd|all_interfaces", "tcp/4444": "nc|all_interfaces"},
                     "users": {"bob": "uid=1000", "toor": "uid=0"}})
    d = drift.compute_drift(a, b)
    got = {(e["map"], e["change"], e["key"]): e["severity"] for e in d["events"]}
    assert got[("suid_sgid", "changed", "/usr/bin/sudo")] == "high"          # hash change on a SUID binary
    assert got[("suid_sgid", "added", "/tmp/x")] == "high"
    assert got[("listening", "added", "tcp/4444")] == "high"                 # new all-interfaces listener
    assert got[("listening", "changed", "tcp/22")] == "high"                 # loopback -> all_interfaces
    assert got[("users", "added", "toor")] == "high"
    assert d["events"][0]["severity"] == "high" and d["counts"]["high"] == 5


def test_drift_does_not_treat_missing_data_as_removal():
    a = _snap("t1", {"suid_sgid": {"/usr/bin/sudo": "h"}, "users": {"bob": "x"}})
    b = _snap("t2", {"users": {"bob": "x"}})                                  # filesystem collector missing this time
    d = drift.compute_drift(a, b)
    assert not d["events"] and {"map": "suid_sgid", "reason": "not collected in both scans"} in d["skipped_maps"]


def test_drift_skips_root_vs_nonroot():
    a, b = _snap("t1", {"suid_sgid": {"/a": "1", "/b": "2"}}), _snap("t2", {"suid_sgid": {"/a": "1"}}, root=False)
    d = drift.compute_drift(a, b)
    assert not d["events"] and "root" in d["skipped_maps"][0]["reason"]


def test_drift_critical_ssh_setting_is_high():
    a, b = _snap("t1", {"ssh_effective": {"permitrootlogin": '"no"', "port": '"22"'}}), _snap("t2", {"ssh_effective": {"permitrootlogin": '"yes"', "port": '"2222"'}})
    sev = {e["key"]: e["severity"] for e in drift.compute_drift(a, b)["events"]}
    assert sev == {"permitrootlogin": "high", "port": "medium"}


# ---------------- anomaly ----------------
def _hist(n, seed=0):
    return synthetic.gen_normal(n, np.random.default_rng(seed))


def test_learning_then_deviations_then_model():
    assert anomaly.analyze(_hist(3))["status"] == "learning"
    r = anomaly.analyze(_hist(12))
    assert r["status"] == "deviations_only" and not r["model_ready"] and r["latest"]["iforest_score"] is None
    r = anomaly.analyze(_hist(35), n_estimators=30)
    assert r["status"] == "ready" and r["latest"]["iforest_score"] is not None and r["timeline"]


def test_forest_is_not_reported_below_min_snapshots():
    assert anomaly.analyze(_hist(29), n_estimators=30)["latest"]["iforest_score"] is None


def test_obvious_structural_change_is_flagged_and_explained():
    h = _hist(40, 1)
    h[-1] = synthetic.apply(h[-1], {"acc_uid0": 1, "fs_suid": 4})
    r = anomaly.analyze(h, n_estimators=30)["latest"]
    assert r["anomalous"] and r["level"] == "alert" and {"acc_uid0", "fs_suid"} <= set(r["flagged_features"])
    assert r["top_deviations"][0]["feature"] in ("acc_uid0", "fs_suid")


def test_ordinary_scan_has_no_feature_alert():
    for seed in range(5):
        assert anomaly.analyze(_hist(40, seed), n_estimators=30)["latest"]["level"] != "alert"


def test_latest_scan_with_few_measured_features_is_not_judged():
    h = _hist(40, 3)
    h[-1]["features"] = {k: (v if i < 10 else None) for i, (k, v) in enumerate(h[-1]["features"].items())}
    r = anomaly.analyze(h, n_estimators=30)
    assert r["status"] == "insufficient_data_latest" and not r["latest"]["anomalous"]


def test_missing_feature_is_imputed_not_treated_as_zero():
    h = _hist(40, 4)
    h[-1]["features"]["fs_suid"] = None                                       # e.g. filesystem collector missing
    r = anomaly.analyze(h, n_estimators=30)["latest"]
    assert "fs_suid" in r["imputed_features"] and r["level"] != "alert"       # imputed, so it cannot raise a feature alert


def test_synthetic_benchmark_mechanics():
    r = synthetic.benchmark(trials=8, n_estimators=30)
    assert r["normal"] <= 0.25
    for k in ("new SUID + new open listeners", "backdoor account + sudo + key", "persistence implant", "C2 beaconing", "tampered binaries", "hardening disabled"):
        assert r[k] >= 0.85, k
    assert r["diffuse shift (22 features +2.5 noise units)"] >= 0.75           # the forest's niche
    assert r["(benign) big pacman -Syu day"] <= 0.25
