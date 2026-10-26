import datetime as dt
import json

import pytest

import rules  # noqa: F401
from engine import runner
from engine.allowlist import load_allowlist, apply_allowlist
from engine.core import REGISTRY, rule, RuleMeta
from engine.loader import Loaded, COLLECTORS
from engine.models import Finding
from tests.helpers import env, run, meta, TS


def test_thirty_rules_registered_with_documented_metadata():
    assert len(REGISTRY) == 30
    for m in REGISTRY.values():
        assert m.why and m.fix and m.title and m.requires, m.id


def test_stale_collector_is_unknown_not_evaluated():
    r = runner.evaluate(REGISTRY["ACC-001"],
                        {"accounts": Loaded.from_envelope("accounts", env("accounts", {"integrity": {"uid0_accounts": ["x"]}}, version="1.1"))},
                        {}, TS)
    assert r.outcome == "unknown" and "Re-run" in r.reason


def test_missing_collector_is_unknown():
    assert run("KRN-001").outcome == "unknown"


def test_rule_exception_is_isolated():
    from engine.core import Ctx
    m = RuleMeta("T-001", "t", 1, "info", "info", "low", "any", {}, (), (), "w", "f", fn=lambda ctx: 1 / 0)
    assert runner.evaluate(m, {}, {}, TS).outcome == "error"


def test_duplicate_subjects_are_merged():
    r = run("FS-002", filesystem={"suid_files": [{"path": "/tmp/a", "mode": "4755"}], "sgid_files": [{"path": "/tmp/a", "mode": "2755"}]})
    assert len(r.findings) == 1 and r.findings[0].evidence_total == 2


def test_evidence_is_capped_but_total_kept():
    files = [{"path": f"/tmp/f{i}", "mode": "4755"} for i in range(25)]
    r = run("FS-002", filesystem={"suid_files": files, "sgid_files": []})
    assert len(r.findings) == 25                      # one finding per subject
    r = run("FS-002", filesystem={"suid_files": [{"path": "/tmp/a"}] * 15, "sgid_files": []})
    assert len(r.findings[0].evidence) <= 10 and r.findings[0].evidence_total == 15


def _f(rule_id="FS-001", subject="/usr/local/bin/x", sha=None):
    return Finding(rule_id, 1, "t", "high", "high", "weakness", subject, attrs={"sha256": sha} if sha else {})


TODAY = dt.date(2026, 10, 21)


def _write(tmp_path, text):
    p = tmp_path / "allow.yaml"
    p.write_text(text)
    return str(p)


def test_allowlist_glob_expiry_and_validation(tmp_path):
    p = _write(tmp_path, """
- {rule_id: FS-001, subject: "/usr/local/bin/*", reason: "my tools", expires: 2027-01-01}
- {rule_id: FS-002, subject: "/tmp/old", reason: "old", expires: 2026-01-01}
- {rule_id: FS-003, subject: "/x"}
""")
    a = load_allowlist(p, TODAY)
    assert len(a["active"]) == 1 and len(a["expired"]) == 1 and len(a["invalid"]) == 1
    f1, f2 = _f(), _f("FS-002", "/tmp/old")
    assert apply_allowlist([f1, f2], a["active"]) == 1
    assert f1.suppressed and f1.suppression["reason"] == "my tools" and not f2.suppressed   # expired: no suppression


def test_allowlist_sha256_must_match(tmp_path):
    p = _write(tmp_path, '- {rule_id: FS-001, subject: "/usr/local/bin/x", sha256: "aa", reason: r, expires: 2027-01-01}')
    a = load_allowlist(p, TODAY)
    f_bad, f_ok = _f(sha="bb"), _f(sha="aa")
    apply_allowlist([f_bad, f_ok], a["active"])
    assert not f_bad.suppressed and f_ok.suppressed


def _write_outputs(tmp_path, **over):
    for n in COLLECTORS:
        d = over.get(n, {})
        (tmp_path / f"{n}.json").write_text(json.dumps(env(n, d)))


def test_run_all_report_shape_and_coverage(tmp_path):
    _write_outputs(tmp_path, accounts={"integrity": {"uid0_accounts": ["root", "toor"]}, "users": [], "account_file_meta": []},
                   kernel={"sysctl": {"kernel.randomize_va_space": 0}, "cmdline": {"params": {}},
                           "reboot_check": {"running_kernel_modules_on_disk": True}, "cpu_mitigations": {}})
    rep = runner.run_all(tmp_path, today=TODAY)
    c = rep["coverage"]
    assert c["rules_total"] == 30 and c["pass"] + c["fail"] + c["unknown"] + c["na"] + c["error"] == 30
    ids = [f["rule_id"] for f in rep["findings"]]
    assert "ACC-001" in ids and "KRN-001" in ids
    assert rep["findings"][0]["severity"] == "critical"               # ranked: critical first
    # processes data is present but empty (no 'processes' list): the rule cannot decide -> UNKNOWN, never PASS
    assert any(u["rule_id"] == "PRC-001" for u in c["unknown_reasons"])


def test_all_suppressed_rule_counts_as_pass(tmp_path):
    _write_outputs(tmp_path, accounts={"integrity": {"uid0_accounts": ["root", "toor"]}, "users": [], "account_file_meta": []})
    allow = tmp_path / "a.yaml"
    allow.write_text('- {rule_id: ACC-001, subject: toor, reason: "lab box", expires: 2027-01-01}')
    rep = runner.run_all(tmp_path, allowlist_path=str(allow), today=TODAY)
    r = next(x for x in rep["rules"] if x["rule_id"] == "ACC-001")
    assert r["outcome"] == "pass" and r["suppressed_count"] == 1
    f = next(f for f in rep["findings"] if f["rule_id"] == "ACC-001")
    assert f["suppressed"] and rep["allowlist"]["applied"] == 1        # still visible in the report (C10)


def test_ranking_severity_then_confidence():
    a = Finding("A", 1, "t", "high", "low", "x", "s", features={"severity_score": 70, "network_exposed": False, "runs_as_root": False})
    b = Finding("B", 1, "t", "high", "high", "x", "s", features={"severity_score": 70, "network_exposed": False, "runs_as_root": False})
    c = Finding("C", 1, "t", "critical", "low", "x", "s", features={})
    assert [f.rule_id for f in sorted([a, b, c], key=runner._rank_key)] == ["C", "B", "A"]


def test_every_rule_has_tests():
    import pathlib
    text = "".join(p.read_text() for p in pathlib.Path(__file__).parent.glob("test_rules_*.py"))
    missing = [rid for rid in REGISTRY if f'"{rid}"' not in text]
    assert not missing, f"rules without tests: {missing}"


def test_cli_min_severity_filter(tmp_path, capsys, monkeypatch):
    import sys
    from engine import __main__ as cli
    _write_outputs(tmp_path, accounts={"integrity": {"uid0_accounts": ["root", "toor"]}, "users": [], "account_file_meta": []})
    monkeypatch.setattr(sys, "argv", ["engine", "--output", str(tmp_path), "--allowlist", str(tmp_path / "none.yaml"),
                                      "--thresholds", str(tmp_path / "none.yaml"), "--min-severity", "high"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "ACC-001" in capsys.readouterr().out          # a critical finding must show with --min-severity high


def test_append_entry_roundtrip(tmp_path):
    from engine.allowlist import append_entry
    p = str(tmp_path / "allow.yaml")
    append_entry(p, {"rule_id": "FS-001", "subject": "/usr/local/bin/x", "reason": "mine",
                     "expires": dt.date(2027, 1, 1), "sha256": "aa"})
    append_entry(p, {"rule_id": "FS-002", "subject": "/tmp/y", "reason": "lab", "expires": dt.date(2027, 2, 1)})
    a = load_allowlist(p, TODAY)
    assert len(a["active"]) == 2 and not a["invalid"] and a["active"][0]["sha256"] == "aa"
