from __future__ import annotations
from engine.core import Unknown, NotApplicable


def under(path: str | None, prefixes) -> bool:
    if not path:
        return False
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def user_procs(ctx) -> list:
    return [p for p in ctx.d("processes").get("processes", []) if not p.get("kernel_thread")]


def suspicious_exec(p: dict, ctx) -> str | None:
    """Why a process's executable looks wrong (memory-only, temp dir, deleted outside package dirs)."""
    if p.get("exe_memfd"):
        return "runs from memory (memfd)"
    if p.get("exe_under_tmp"):
        return "executes from a temp directory"
    if p.get("exe_deleted") and not under(p.get("exe"), ctx.th("package_dirs")):
        return "executable deleted from disk (outside /usr and /opt)"
    return None


def ssh_effective(ctx) -> dict:
    ssh = ctx.d("configs").get("ssh")
    if ssh is None:
        raise Unknown("configs.ssh section missing (section failed)")
    if not ssh.get("installed", True):
        raise NotApplicable("sshd not installed")
    eff = ssh.get("effective")
    if eff is None:
        raise Unknown(f"effective sshd config unavailable: {ssh.get('effective_error') or 'sshd -T failed'}")
    return {k.lower(): v for k, v in eff.items()}


def one(v):
    """sshd -T values are str, or list when a key repeats; take the first."""
    return (v[0] if isinstance(v, list) and v else v)


def sshd_reachability(ctx):
    """(reachable: True/False/None, loopback_only: True/False/None)."""
    reachable = None
    if ctx.has("services"):
        sd = ctx.d("services")
        if sd.get("services") is not None:
            hit = any(s.get("name") in ("sshd.service", "ssh.service")
                      and (s.get("sub") == "running" or s.get("unit_file_state") == "enabled")
                      for s in sd["services"])
            hit = hit or any(s.get("name") in ("sshd.socket", "ssh.socket")
                             and (s.get("active") == "active" or s.get("unit_file_state") == "enabled")
                             for s in sd.get("sockets") or [])
            reachable = hit
    loopback_only = None
    if ctx.has("network"):
        ls = [l for l in ctx.d("network").get("listening", [])
              if l.get("proto") == "tcp" and l.get("process") in ("sshd", "sshd-session")]
        if ls:
            reachable = True
            loopback_only = all(l.get("scope") == "loopback" for l in ls)
    return reachable, loopback_only


def firewall_state(ctx):
    """('filtering' | 'none' | 'unknown', details)."""
    fw = ctx.d("network").get("firewall")
    if fw is None:
        raise Unknown("network.firewall not collected")
    filtering, unreadable = [], []
    nft = fw.get("nftables")
    if nft:
        if nft.get("readable"):
            if any(c.get("hook") == "input" and (c.get("policy") == "drop" or c.get("rule_count", 0) > 0)
                   for c in nft.get("base_chains", [])):
                filtering.append("nftables")
        else:
            unreadable.append("nftables")
    for tool, v in (fw.get("iptables") or {}).items():
        if v.get("readable"):
            pol = (v.get("policies") or {}).get("INPUT")
            if pol in ("DROP", "REJECT") or v.get("rule_count", 0) > 0:
                filtering.append(tool)
        else:
            unreadable.append(tool)
    ufw = fw.get("ufw")
    if ufw:
        if ufw.get("readable"):
            if ufw.get("status") == "active":
                filtering.append("ufw")
        else:
            unreadable.append("ufw")
    fd = fw.get("firewalld")
    if fd and fd.get("state") == "running":
        filtering.append("firewalld")
    if filtering:
        return "filtering", filtering
    if unreadable:
        return "unknown", unreadable
    return "none", fw.get("frameworks_present", [])


def nonloopback_listeners(ctx) -> list:
    return [l for l in ctx.d("network").get("listening", []) if l.get("scope") != "loopback"]


def iter_persistence(d: dict):
    """Yield (section, record) for every file-like record in the persistence collector output."""
    cron = d.get("cron") or {}
    for key in ("system", "user", "scripts"):
        for r in cron.get(key) or []:
            yield f"cron.{key}", r
    for r in (d.get("systemd") or {}).get("local_units") or []:
        yield "systemd.local_units", r
    sh = d.get("shell") or {}
    for r in sh.get("system") or []:
        yield "shell.system", r
    for user, recs in (sh.get("users") or {}).items():
        for r in recs:
            yield f"shell.users.{user}", r
    misc = d.get("misc") or {}
    for key in ("ld_so_conf_files", "pacman_hooks", "udev_rules_local", "modules_load_d"):
        for r in misc.get(key) or []:
            yield f"misc.{key}", r
    for r in d.get("ssh_authorized_keys") or []:
        yield "ssh_authorized_keys", r


def writable_by_others(m: dict | None) -> bool:
    """World-writable, or group-writable by a group other than root (heuristic; documented in the spec)."""
    if not m or not m.get("exists"):
        return False
    return bool(m.get("world_writable")) or (bool(m.get("group_writable")) and m.get("group") not in (None, "root"))
