from tests.helpers import run, meta, subjects, sev, proc, TS
import datetime as dt


# ---------------- CFG ----------------
def _ssh(eff=None, installed=True, **extra):
    return {"ssh": {"installed": installed, "effective": eff, "match_blocks": 0, **extra}}


SVC_UP = {"services": {"services": [{"name": "sshd.service", "sub": "running", "unit_file_state": "enabled"}], "sockets": []}}
SVC_DOWN = {"services": {"services": [{"name": "sshd.service", "sub": "dead", "unit_file_state": "disabled"}], "sockets": []}}


def test_cfg001():
    assert sev(run("CFG-001", configs=_ssh({"permitrootlogin": "yes"}), **SVC_UP)) == {"sshd PermitRootLogin": "high"}
    assert sev(run("CFG-001", configs=_ssh({"permitrootlogin": "yes"}), **SVC_DOWN)) == {"sshd PermitRootLogin": "low"}
    assert run("CFG-001", configs=_ssh({"permitrootlogin": "prohibit-password"})).outcome == "pass"
    r = run("CFG-001", configs=_ssh(None, effective_error="no hostkeys available"))
    assert r.outcome == "unknown" and "hostkeys" in r.reason
    assert run("CFG-001", configs=_ssh(installed=False)).outcome == "na"
    assert run("CFG-001", roots={"configs": False}, configs=_ssh({"permitrootlogin": "yes"})).outcome == "unknown"


def test_cfg002():
    assert sev(run("CFG-002", configs=_ssh({"permitemptypasswords": "yes"})))["sshd PermitEmptyPasswords"] == "critical"
    assert run("CFG-002", configs=_ssh({"permitemptypasswords": "no"})).outcome == "pass"


def test_cfg003():
    eff = {"passwordauthentication": "yes"}
    assert sev(run("CFG-003", configs=_ssh(eff), **SVC_UP))["sshd PasswordAuthentication"] == "medium"
    assert run("CFG-003", configs=_ssh(eff), **SVC_DOWN).outcome == "pass"
    net = {"network": {"listening": [{"proto": "tcp", "process": "sshd", "scope": "loopback", "port": 22}]}}
    assert sev(run("CFG-003", configs=_ssh(eff), **SVC_UP, **net))["sshd PasswordAuthentication"] == "low"
    assert run("CFG-003", configs=_ssh({"passwordauthentication": "no"}), **SVC_UP).outcome == "pass"
    r = run("CFG-003", configs=_ssh(eff, match_blocks=2), **SVC_UP)
    assert any("Match" in e["expected"] for e in r.findings[0].evidence)       # honest about sshd -T limits


def _sudoers(entries=(), defaults=None, files=(), ignored=(), readable=True):
    return {"sudoers": {"installed": True, "readable": readable, "entries": list(entries),
                        "global_defaults": defaults or {}, "files": list(files), "ignored_files": list(ignored)}}


def _spec(raw, **kw):
    e = {"type": "userspec", "file": "/etc/sudoers", "line": 1, "raw": raw, "who": ["alice"], "runas": "ALL",
         "runas_all": True, "nopasswd": False, "runs_all_commands": False, "has_wildcard_command": False}
    e.update(kw)
    return e


def test_cfg004():
    r = run("CFG-004", configs=_sudoers([_spec("a ALL=(ALL) NOPASSWD: ALL", nopasswd=True, runs_all_commands=True)]))
    assert list(sev(r).values()) == ["high"]
    r = run("CFG-004", configs=_sudoers([_spec("a ALL=NOPASSWD: ALL", nopasswd=True, runs_all_commands=True, runas=None, runas_all=False)]))
    assert list(sev(r).values()) == ["high"]                                  # implicit root runas
    r = run("CFG-004", configs=_sudoers([_spec("a ALL=(root) /bin/x *", has_wildcard_command=True)]))
    assert list(sev(r).values()) == ["medium"]
    assert run("CFG-004", configs=_sudoers([_spec("%wheel ALL=(ALL:ALL) ALL", runs_all_commands=True)])).outcome == "pass"
    assert run("CFG-004", configs=_sudoers(readable=False)).outcome == "unknown"


def test_cfg005():
    good = meta("/etc/sudoers", "0440")
    assert run("CFG-005", configs=_sudoers(files=[good])).outcome == "pass"
    assert run("CFG-005", configs=_sudoers(defaults={"authenticate": False}, files=[good])).outcome == "fail"
    assert run("CFG-005", configs=_sudoers(defaults={"env_keep": "HOME LD_PRELOAD"}, files=[good])).outcome == "fail"
    assert run("CFG-005", configs=_sudoers(defaults={"env_reset": False}, files=[good])).outcome == "fail"
    assert run("CFG-005", configs=_sudoers(files=[meta("/etc/sudoers.d/x", "0644")])).outcome == "fail"
    r = run("CFG-005", configs=_sudoers(files=[good], ignored=["/etc/sudoers.d/a.conf"]))
    assert sev(r) == {"/etc/sudoers.d/a.conf": "low"}


# ---------------- NET ----------------
def _l(port, scope="all_interfaces", proto="tcp", **kw):
    return {"proto": proto, "port": port, "address": "0.0.0.0", "scope": scope, "process": "p", "user": "root", **kw}


def _net(listening=(), fw=None, sockets=()):
    return {"network": {"listening": list(listening), "special_sockets": list(sockets),
                        "firewall": fw if fw is not None else {"frameworks_present": []}, "connections": {"list": []}}}


def test_net001():
    r = run("NET-001", **_net([_l(2375), _l(3306, "loopback"), _l(5432, "private"), _l(8080), _l(5432, "all_interfaces")]))
    assert sev(r) == {"tcp/2375": "critical", "tcp/5432": "high"}
    assert run("NET-001", **_net([_l(3306, "loopback")])).outcome == "pass"


NFT_ON = {"frameworks_present": ["nftables"], "nftables": {"readable": True, "base_chains": [{"hook": "input", "policy": "drop", "rule_count": 0}]}}
NFT_OFF = {"frameworks_present": ["nftables"], "nftables": {"readable": True, "base_chains": [{"hook": "input", "policy": "accept", "rule_count": 0}]}}
NFT_UNREADABLE = {"frameworks_present": ["nftables"], "nftables": {"readable": False, "error": "Operation not permitted"}}


def test_net002():
    assert sev(run("NET-002", **_net([_l(8080)], NFT_OFF))) == {"host firewall": "medium"}
    assert sev(run("NET-002", **_net([_l(8080), _l(445)], NFT_OFF))) == {"host firewall": "high"}
    assert run("NET-002", **_net([_l(8080)], NFT_ON)).outcome == "pass"
    assert run("NET-002", **_net([_l(8080)], NFT_UNREADABLE)).outcome == "unknown"       # blind != open
    assert run("NET-002", **_net([_l(8080, "loopback")], NFT_OFF)).outcome == "pass"
    assert run("NET-002", **_net([_l(8080)], {"frameworks_present": []})).outcome == "fail"
    ufw = {"frameworks_present": ["ufw"], "ufw": {"readable": True, "status": "active"}}
    assert run("NET-002", **_net([_l(8080)], ufw)).outcome == "pass"
    ipt = {"frameworks_present": ["iptables"], "iptables": {"iptables": {"readable": True, "policies": {"INPUT": "DROP"}, "rule_count": 0}}}
    assert run("NET-002", **_net([_l(8080)], ipt)).outcome == "pass"


def test_net003():
    r = run("NET-003", **_net(sockets=[meta("/var/run/docker.sock", "0666"), meta("/run/libvirt/libvirt-sock", "0660")]))
    assert sev(r) == {"/var/run/docker.sock": "critical"}
    assert run("NET-003", **_net(sockets=[meta("/var/run/docker.sock", "0660", group="docker")])).outcome == "pass"


# ---------------- LOG ----------------
TS_EPOCH = dt.datetime.fromisoformat(TS).timestamp()


def _infra(storage="persistent", has_dir=True, oldest_days=30, present=True):
    return {"logs": {"infrastructure": {"journalctl_present": present, "journald_config": {"Storage": storage},
                                        "persistent_journal_dir_exists": has_dir,
                                        "journal_span": {"oldest_epoch": int(TS_EPOCH - oldest_days * 86400) if oldest_days is not None else None}}}}


def test_log001():
    assert run("LOG-001", **_infra()).outcome == "pass"
    assert subjects(run("LOG-001", **_infra(storage="auto", has_dir=False))) == ["journal-persistence"]
    assert subjects(run("LOG-001", **_infra(storage="volatile"))) == ["journal-persistence"]
    assert subjects(run("LOG-001", **_infra(oldest_days=2))) == ["journal-retention"]
    assert run("LOG-001", **_infra(oldest_days=None)).outcome == "unknown"
    assert run("LOG-001", **_infra(present=False)).outcome == "unknown"


def _ssh_events(accepted, failed=()):
    return {"logs": {"events": {"ssh": {"accepted": list(accepted),
                                        "top_failed_sources": [{"value": v, "count": c} for v, c in failed]}}}}


def test_log002():
    acc = lambda u, ip, scope="public": {"user": u, "source": ip, "method": "password", "count": 1, "scope": scope}
    assert subjects(run("LOG-002", **_ssh_events([acc("arc", "1.2.3.4")], [("1.2.3.4", 9)]))) == ["arc@1.2.3.4"]
    assert subjects(run("LOG-002", **_ssh_events([acc("root", "8.8.8.8")]))) == ["root@8.8.8.8"]
    assert run("LOG-002", **_ssh_events([acc("arc", "192.168.1.5", "private")], [("1.2.3.4", 99)])).outcome == "pass"
    assert run("LOG-002", **_ssh_events([acc("arc", "1.2.3.4")], [("1.2.3.4", 2)])).outcome == "pass"
    assert run("LOG-002", logs={"events": None}).outcome == "unknown"


# ---------------- KRN ----------------
def _k(sysctl=None, params=None):
    return {"kernel": {"sysctl": sysctl or {}, "cmdline": {"params": params or {}}}}


def test_krn001():
    assert subjects(run("KRN-001", **_k({"kernel.randomize_va_space": 0}))) == ["kernel.randomize_va_space"]
    assert subjects(run("KRN-001", **_k({"kernel.randomize_va_space": 2}, {"mitigations": "off"}))) == ["cmdline: mitigations=off"]
    assert subjects(run("KRN-001", **_k({"kernel.randomize_va_space": 2}, {"nokaslr": True}))) == ["cmdline: nokaslr"]
    assert run("KRN-001", **_k({"kernel.randomize_va_space": 2}, {"quiet": True})).outcome == "pass"
    assert run("KRN-001", **_k({"kernel.randomize_va_space": None})).outcome == "unknown"


def test_krn002():
    r = run("KRN-002", **_k({"kernel.yama.ptrace_scope": 0, "fs.protected_symlinks": 1, "kernel.kptr_restrict": 0}))
    assert subjects(r) == ["kernel.kptr_restrict", "kernel.yama.ptrace_scope"]
    assert run("KRN-002", **_k({"kernel.yama.ptrace_scope": 1})).outcome == "pass"
    from engine.config import load_thresholds as _lt
    safe = {k: (1 if v == 0 else 0) for k, v in _lt()["weak_sysctls"].items()}
    safe["kernel.yama.ptrace_scope"] = None                                                  # one absent key is normal
    assert run("KRN-002", **_k(safe)).outcome == "pass"
    from engine.config import load_thresholds
    assert run("KRN-002", **_k({k: None for k in load_thresholds()["weak_sysctls"]})).outcome == "unknown"


def _kr(on_disk=True, cpu=None):
    return {"kernel": {"reboot_check": {"running_kernel_modules_on_disk": on_disk, "running_release": "6.1"},
                       "cpu_mitigations": cpu if cpu is not None else {"meltdown": "Not affected"}}}


def test_krn003():
    assert subjects(run("KRN-003", **_kr(on_disk=False))) == ["running-kernel"]
    assert subjects(run("KRN-003", **_kr(cpu={"mds": "Vulnerable: Clear CPU buffers attempted", "x": "Mitigation: PTI"}))) == ["cpu: mds"]
    assert run("KRN-003", **_kr()).outcome == "pass"
    assert run("KRN-003", **_kr(on_disk=None)).outcome == "unknown"


# ---------------- PER ----------------
def _per(cron=None, systemd=None, shell=None, misc=None, keys=()):
    return {"persistence": {"users_scanned": ["arc"], "cron": cron if cron is not None else {"system": [], "user": [], "scripts": []},
                            "systemd": systemd if systemd is not None else {"local_units": []},
                            "shell": shell if shell is not None else {"system": [], "users": {}},
                            "misc": misc if misc is not None else {"ld_so_preload": {"entries": []}},
                            "ssh_authorized_keys": list(keys)}}


def test_per001():
    bad = {"path": "/etc/cron.d/x", "pattern_hits": ["dev_tcp"]}
    assert subjects(run("PER-001", **_per(cron={"system": [bad], "user": [], "scripts": []}))) == ["/etc/cron.d/x"]
    unit = {"path": "/etc/systemd/system/e.service", "pattern_hits": [], "exec_paths": ["/home/a/run"]}
    assert subjects(run("PER-001", **_per(systemd={"local_units": [unit]}))) == ["/etc/systemd/system/e.service"]
    tmp = {"path": "/home/a/.bashrc", "pattern_hits": ["runs_from_tmp"]}
    r = run("PER-001", **_per(shell={"system": [], "users": {"a": [tmp]}}))
    assert r.findings[0].severity == "medium" and r.findings[0].confidence == "low"
    ok = {"path": "/home/a/.bashrc", "pattern_hits": ["ld_preload"]}
    assert run("PER-001", **_per(shell={"system": [], "users": {"a": [ok]}})).outcome == "pass"
    assert run("PER-001", **_per(cron=None, shell=None)).outcome == "pass"   # all sections present by default
    p = _per(); p["persistence"]["cron"] = None
    assert run("PER-001", **p).outcome == "unknown"                          # a failed section is not a pass


def test_per002():
    assert subjects(run("PER-002", **_per(misc={"ld_so_preload": {"entries": ["/lib/evil.so"]}}))) == ["/etc/ld.so.preload"]
    ww = {"path": "/etc/cron.d/x", "world_writable": True}
    assert subjects(run("PER-002", **_per(cron={"system": [ww], "user": [], "scripts": []}))) == ["/etc/cron.d/x"]
    own = {"path": "/home/a/.bashrc", "group_writable": True, "group": "a", "owner": "a"}
    assert run("PER-002", **_per(shell={"system": [], "users": {"a": [own]}})).outcome == "pass"   # private group
    shared = {"path": "/home/a/.profile", "group_writable": True, "group": "users", "owner": "a"}
    assert run("PER-002", **_per(shell={"system": [], "users": {"a": [shared]}})).outcome == "fail"
    key = {"path": "/home/a/.ssh/authorized_keys", "group_writable": True, "mode": "0664", "ssh_dir_meta": {"path": "/home/a/.ssh"}}
    assert run("PER-002", **_per(keys=[key])).outcome == "fail"
    assert run("PER-002", **_per()).outcome == "pass"


# ---------------- X ----------------
def _x(conns, procs):
    return {"network": {"connections": {"list": conns}}, "processes": {"processes": procs}}


def test_x001():
    c = {"pid": 7, "process": "agent", "remote_scope": "public", "remote_address": "8.8.8.8", "remote_port": 443}
    sus = proc(pid=7, name="agent", exe="/memfd:a", exe_memfd=True)
    assert subjects(run("X-001", **_x([c], [sus]))) == ["/memfd:a -> 8.8.8.8:443"]
    assert run("X-001", **_x([c], [proc(pid=7, name="agent")])).outcome == "pass"
    assert run("X-001", **_x([c], [proc(pid=7, name="other", exe_memfd=True)])).outcome == "pass"      # pid reuse
    assert run("X-001", **_x([{**c, "remote_scope": "private"}], [sus])).outcome == "pass"
    assert run("X-001", **_x([{**c, "pid": None}], [sus])).outcome == "unknown"
