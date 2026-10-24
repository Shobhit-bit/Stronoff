from engine.core import rule, ev, Unknown
from ._helpers import user_procs, under, suspicious_exec


@rule(id="PRC-001", title="Process executes from memory or a temp directory", category="ioc", severity="high",
      confidence="medium",
      why="Legitimate software is installed on disk in package directories. Running from memory (memfd) or /tmp is consistent with malware, droppers or fileless tools.",
      fix="Verify the process: ls -l /proc/<pid>/exe, its parent, and its network connections. Container runtimes and some JITs use memfd legitimately: allowlist by process name once confirmed.",
      requires={"processes": ["processes"]})
def prc_001(ctx):
    groups, unreadable = {}, 0
    for p in user_procs(ctx):
        if p.get("exe_readable") is False:
            unreadable += 1
        if p.get("exe_memfd") or p.get("exe_under_tmp"):
            groups.setdefault(p.get("exe") or p["name"], []).append(p)
    for key, ps in groups.items():
        p = ps[0]
        why = "runs from memory (memfd)" if p.get("exe_memfd") else "executes from a temp directory"
        ctx.fail(key, [ev("processes", "processes[]", f"{why}; pids {[x['pid'] for x in ps]}; user {p.get('user')}; cmdline {p.get('cmdline')}",
                          "executable on disk in a package directory")],
                 runs_as_root=any(x.get("user") == "root" for x in ps))
    if unreadable:
        ctx.partial(f"{unreadable} process executable(s) unreadable (run as root)")


@rule(id="PRC-002", title="Running binary was deleted from disk", category="ioc", severity="high",
      confidence="medium",
      why="A process whose executable no longer exists outside package directories is a common way for malware to hide. Inside /usr it usually just means an update replaced the file.",
      fix="Outside /usr and /opt: verify with ls -l /proc/<pid>/exe and recover/inspect the binary. Inside /usr: restart the listed service or reboot to pick up the update.",
      requires={"processes": ["processes"]})
def prc_002(ctx):
    restart: dict = {}
    for p in user_procs(ctx):
        if not p.get("exe_deleted") or p.get("exe_memfd") or p.get("exe_under_tmp") or not p.get("exe"):
            continue                                    # memfd/tmp are PRC-001's
        if under(p["exe"], ctx.th("package_dirs")):
            restart.setdefault(p.get("package") or p["exe"], []).append(p)
        else:
            ctx.fail(p["exe"], [ev("processes", "processes[]", f"pid {p['pid']} user {p.get('user')} cmdline {p.get('cmdline')}",
                                   "executable still present on disk")], runs_as_root=p.get("user") == "root")
    for key, ps in restart.items():
        ctx.fail(f"restart needed: {key}", [ev("processes", "processes[]", f"pids {[x['pid'] for x in ps]} still running the pre-update binary",
                                              "restart after update")],
                 severity="info", title="Running binary replaced by an update (restart needed)",
                 why="A package update replaced the file but the old version is still running in memory, so any fix in the update is not active yet.",
                 fix="Restart the affected services (or reboot).", runs_as_root=any(x.get("user") == "root" for x in ps))


@rule(id="PRC-003", title="Hidden process IDs", category="ioc", severity="critical", confidence="medium",
      why="A PID that answers kill(pid, 0) but is absent from /proc listings is the signature of a kernel rootkit hiding processes.",
      fix="Re-run the sweep to rule out a race with short-lived tasks. If it persists, assume compromise: boot from trusted media and inspect offline.",
      requires={"processes": ["hidden_pid_check"]})
def prc_003(ctx):
    h = ctx.d("processes")["hidden_pid_check"]
    if not h.get("performed"):
        raise Unknown("hidden-PID sweep was not performed (fast mode / --no-hidden-check)")
    for pid in h.get("suspected_hidden_pids", []):
        ctx.fail(f"pid {pid}", [ev("processes", "hidden_pid_check.suspected_hidden_pids", pid, "no PID hidden from /proc")],
                 runs_as_root=True)
