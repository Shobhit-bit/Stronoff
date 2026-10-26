from tests.helpers import run, meta, subjects, sev, proc


# ---------------- ACC ----------------
def test_acc001():
    assert run("ACC-001", accounts={"integrity": {"uid0_accounts": ["root", "toor"]}}).outcome == "fail"
    assert subjects(run("ACC-001", accounts={"integrity": {"uid0_accounts": ["root", "toor"]}})) == ["toor"]
    assert run("ACC-001", accounts={"integrity": {"uid0_accounts": ["root"]}}).outcome == "pass"
    assert run("ACC-001").outcome == "unknown"                       # accounts.json missing


def _users(state="empty", login=True):
    return {"users": [{"name": "bob", "uid": 1000, "has_login_shell": login, "password": {"state": state}}]}


def test_acc002():
    pam_ok = {"pam": {"summary": {"nullok_files": ["system-auth"]}}}
    r = run("ACC-002", accounts=_users(), configs=pam_ok)
    assert sev(r) == {"bob": "critical"}
    r = run("ACC-002", accounts=_users(), configs={"pam": {"summary": {"nullok_files": []}}})
    assert sev(r) == {"bob": "low"}
    assert sev(run("ACC-002", accounts=_users()))["bob"] == "critical"          # PAM unknown -> worst case
    assert run("ACC-002", accounts=_users("set"), configs=pam_ok).outcome == "pass"
    assert run("ACC-002", accounts=_users(login=False), configs=pam_ok).outcome == "pass"
    assert run("ACC-002", roots={"accounts": False}, accounts=_users()).outcome == "unknown"
    nodata = {"users": [{"name": "bob", "uid": 1000, "has_login_shell": True, "password": None}]}
    assert run("ACC-002", accounts=nodata).outcome == "unknown"


# ---------------- FS ----------------
def _suid(path, owned=False, **kw):
    return {"path": path, "mode": "4755", "owner": "root", "owned_by_package": owned, "package": None,
            "sha256": "ab" * 32, **kw}


def _fs(suid=(), sgid=()):
    return {"filesystem": {"suid_files": list(suid), "sgid_files": list(sgid)}}


def test_fs001():
    r = run("FS-001", **_fs([_suid("/usr/local/bin/tool")]))
    assert subjects(r) == ["/usr/local/bin/tool"] and r.findings[0].attrs["sha256"] == "ab" * 32
    assert run("FS-001", **_fs([_suid("/usr/bin/sudo", owned=True)])).outcome == "pass"
    assert run("FS-001", **_fs([_suid("/usr/bin/x", owned=None)])).outcome == "unknown"
    assert run("FS-001", **_fs([_suid("/home/a/t")])).outcome == "pass"      # FS-002's job
    assert run("FS-001", **_fs([_suid("/usr/local/bin/t")], [_suid("/usr/local/bin/t")])).findings[0].evidence_total == 2


def test_fs002():
    assert subjects(run("FS-002", **_fs([_suid("/home/a/t"), _suid("/tmp/x")]))) == ["/home/a/t", "/tmp/x"]
    assert run("FS-002", **_fs([_suid("/usr/bin/sudo", owned=True)])).outcome == "pass"


def _ww(files=(), dirs=(), denied=0):
    return {"filesystem": {"world_writable_files": list(files), "world_writable_dirs_no_sticky": list(dirs),
                           "scan": {"denied_dirs": denied}}}


def test_fs003():
    r = run("FS-003", **_ww([{"path": "/etc/x", "mode": "0666"}, {"path": "/home/a/f", "mode": "0666"}]))
    assert sev(r) == {"/etc/x": "high", "/home/a/f": "medium"}
    assert run("FS-003", **_ww()).outcome == "pass"
    r = run("FS-003", **_ww(denied=3))
    assert r.outcome == "unknown" and "unreadable" in r.reason            # partial scan: not a pass
    assert run("FS-003", **_ww([{"path": "/etc/x", "mode": "0666"}], denied=3)).outcome == "fail"


def test_fs004():
    paths = [meta("/etc/shadow", "0644"), meta("/etc/passwd", "0664", group="users"), meta("/etc/sudoers", "0440"),
             meta("/etc/fstab", "0664", group="root"), meta("/etc/ssh/sshd_config", "0666")]
    r = run("FS-004", filesystem={"sensitive_paths": paths})
    assert sev(r) == {"/etc/shadow": "critical", "/etc/passwd": "critical", "/etc/ssh/sshd_config": "high"}
    assert run("FS-004", filesystem={"sensitive_paths": [meta("/etc/shadow", "0600")]}).outcome == "pass"
    r = run("FS-004", filesystem={"sensitive_paths": [{"path": "/etc/shadow", "exists": None}]})
    assert r.outcome == "unknown"
    # account_file_meta from the accounts collector is also checked
    r = run("FS-004", filesystem={"sensitive_paths": []}, accounts={"account_file_meta": [meta("/etc/gshadow", "0644")]})
    assert sev(r) == {"/etc/gshadow": "critical"}


# ---------------- PRC ----------------
def _p(*procs):
    return {"processes": {"processes": list(procs)}}


def test_prc001():
    r = run("PRC-001", **_p(proc(exe="/tmp/a", exe_under_tmp=True), proc(pid=2, exe="/memfd:x", exe_memfd=True),
                           proc(pid=3)))
    assert subjects(r) == ["/memfd:x", "/tmp/a"]
    assert run("PRC-001", **_p(proc())).outcome == "pass"
    assert run("PRC-001", **_p(proc(exe=None, exe_readable=False))).outcome == "unknown"
    assert run("PRC-001", **_p({"pid": 2, "kernel_thread": True, "name": "kthreadd"})).outcome == "pass"


def test_prc002():
    r = run("PRC-002", **_p(proc(exe="/opt/evil", exe_deleted=True, package=None),
                           proc(pid=2, exe="/usr/bin/sshd", exe_deleted=True, package="openssh"),
                           proc(pid=3, exe="/usr/bin/sshd", exe_deleted=True, package="openssh"),
                           proc(pid=4, exe="/memfd:z", exe_deleted=True, exe_memfd=True)))
    assert sev(r)["restart needed: openssh"] == "info"
    assert r.findings and next(f for f in r.findings if f.subject == "restart needed: openssh").evidence_total == 1
    # /opt is a package dir -> restart-needed, not an alarm; anything else deleted is High
    r = run("PRC-002", **_p(proc(exe="/home/a/x", exe_deleted=True)))
    assert sev(r) == {"/home/a/x": "high"}
    assert run("PRC-002", **_p(proc())).outcome == "pass"


def test_prc003():
    ok = {"processes": {"hidden_pid_check": {"performed": True, "suspected_hidden_pids": [4242]}}}
    assert sev(run("PRC-003", **ok)) == {"pid 4242": "critical"}
    assert run("PRC-003", processes={"hidden_pid_check": {"performed": True, "suspected_hidden_pids": []}}).outcome == "pass"
    assert run("PRC-003", processes={"hidden_pid_check": {"performed": False}}).outcome == "unknown"


# ---------------- SVC ----------------
def _svc(name="a.service", user="root", sub="running", execs=(), frag=None, dropins=()):
    return {"name": name, "effective_user": user, "sub": sub, "exec_start": list(execs),
            "fragment_meta": frag, "dropin_meta": list(dropins)}


def _sd(*s):
    return {"services": {"services": list(s)}}


def test_svc001():
    bad = meta("/usr/bin/a", "0666")
    assert sev(run("SVC-001", **_sd(_svc(execs=[bad])))) == {"a.service": "critical"}
    assert sev(run("SVC-001", **_sd(_svc(user="www", execs=[bad])))) == {"a.service": "high"}
    assert sev(run("SVC-001", **_sd(_svc(frag=meta("/etc/systemd/system/a.service", "0664", group="users"))))) == {"a.service": "critical"}
    assert run("SVC-001", **_sd(_svc(execs=[meta("/usr/bin/a", "0755")], frag=meta("/u/a.service")))).outcome == "pass"
    assert run("SVC-001", services={"systemd_available": True, "manager_running": False}).outcome == "unknown"


def test_svc002():
    ex = lambda own: {"path": "/opt/x/bin", "exists": True, "owned_by_package": own}
    assert subjects(run("SVC-002", **_sd(_svc(execs=[ex(False)])))) == ["a.service"]
    assert run("SVC-002", **_sd(_svc(execs=[ex(True)]))).outcome == "pass"
    assert run("SVC-002", **_sd(_svc(execs=[ex(None)]))).outcome == "unknown"
    assert run("SVC-002", **_sd(_svc(user="www", execs=[ex(False)]))).outcome == "pass"
    assert run("SVC-002", **_sd(_svc(sub="dead", execs=[ex(False)]))).outcome == "pass"


# ---------------- PKG ----------------
def _conf(glob=None, repos=()):
    return {"packages": {"pacman_available": True,
                         "pacman_conf": {"options": {"SigLevel": [glob]} if glob else {},
                                         "repos": [{"name": n, "sig_level": s} for n, s in repos]}}}


def test_pkg001():
    assert sev(run("PKG-001", **_conf("Never")))["global SigLevel"] == "high"
    assert sev(run("PKG-001", **_conf(repos=[("extra", "Never")])))["repo [extra]"] == "high"
    assert sev(run("PKG-001", **_conf("Optional TrustAll")))["global SigLevel"] == "medium"
    assert sev(run("PKG-001", **_conf("PackageRequired DatabaseNever")))["global SigLevel"] == "high"
    assert run("PKG-001", **_conf("Required DatabaseOptional")).outcome == "pass"
    assert run("PKG-001", **_conf()).outcome == "pass"
    assert run("PKG-001", packages={"pacman_available": False}).outcome == "na"


def _upd(days, pending=None):
    return {"packages": {"pacman_available": True, "updates": {"last_full_upgrade": {"days_ago": days}, "pending": pending}}}


def test_pkg002():
    assert sev(run("PKG-002", **_upd(45, [1, 2])))["system"] == "medium"
    assert sev(run("PKG-002", **_upd(100)))["system"] == "high"
    assert run("PKG-002", **_upd(5)).outcome == "pass"
    assert run("PKG-002", **_upd(None)).outcome == "unknown"


def _integ(files, performed=True):
    return {"packages": {"pacman_available": True, "integrity": {"performed": performed, "altered_files": files}}}


def test_pkg003():
    f = lambda p, cc: {"path": p, "package": "x", "reasons": ["Size mismatch"], "content_changed": cc}
    r = run("PKG-003", **_integ([f("/usr/bin/sudo", True), f("/usr/bin/ls", True), f("/usr/bin/cat", False),
                               f("/usr/lib/security/pam_unix.so", True)]))
    assert sev(r) == {"/usr/bin/sudo": "critical", "/usr/bin/ls": "high", "/usr/lib/security/pam_unix.so": "critical"}
    assert run("PKG-003", **_integ([f("/usr/bin/cat", False)])).outcome == "pass"
    assert run("PKG-003", **_integ([], performed=False)).outcome == "unknown"
