"""Build a Snapshot (features + comparison maps) from one scan, and decide whether it IS one scan."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
from pathlib import Path

from engine.core import dig
from engine.loader import load_all
from . import MAX_SCAN_SPREAD_MIN
from .features import extract


def _h(obj) -> str:
    return hashlib.sha1(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


def _d(L, c, path=None):
    l = L.get(c)
    if not l or not l.usable:
        return None
    return l.data if path is None else dig(l.data, path)


def _recs(d):
    """All file-like persistence records as {path: sha256}."""
    from rules._helpers import iter_persistence
    return {r["path"]: r.get("sha256") or "" for s, r in iter_persistence(d) if r.get("path") and s != "ssh_authorized_keys"}


# Each map: (collector, builder(L) -> dict[str, str] | None). None = could not be collected -> not compared.
def _m_suid(L):
    d = _d(L, "filesystem")
    if d is None or d.get("suid_files") is None:
        return None
    return {f["path"]: f.get("sha256") or f"mode:{f.get('mode')}" for f in d["suid_files"] + d["sgid_files"]}


def _m_listening(L):
    ls = _d(L, "network", "listening")
    if ls is None:
        return None
    m: dict = {}
    for l in ls:
        k = f"{l['proto']}/{l['port']}"
        m.setdefault(k, set()).add(f"{l.get('process') or '?'}|{l.get('scope')}")
    return {k: ",".join(sorted(v)) for k, v in m.items()}


def _m_users(L):
    us = _d(L, "accounts", "users")
    if us is None:
        return None
    return {u["name"]: f"uid={u['uid']} shell={u['shell']} login={u['has_login_shell']} groups={','.join(u.get('privileged_groups', []))}" for u in us}


def _m_privgroups(L):
    p = _d(L, "accounts", "privileged_group_members")
    return None if p is None else {g: ",".join(sorted(m)) for g, m in p.items()}


def _m_services(L):
    s = _d(L, "services", "services")
    if s is None:
        return None
    return {x["name"]: f"{x.get('sub')}|{x.get('unit_file_state')}|{x.get('effective_user')}" for x in s}


def _m_timers(L):
    t = _d(L, "persistence", "systemd.timer_unit_files")
    return None if t is None else {x["name"]: x["state"] for x in t}


def _m_local_units(L):
    u = _d(L, "persistence", "systemd.local_units")
    return None if u is None else {x["path"]: x.get("sha256") or "" for x in u}


def _m_cron(L):
    c = _d(L, "persistence", "cron")
    if c is None:
        return None
    return {r["path"]: r.get("sha256") or "" for k in ("system", "user", "scripts") for r in c.get(k) or []}


def _m_shell(L):
    s = _d(L, "persistence", "shell")
    if s is None:
        return None
    recs = list(s.get("system") or []) + [r for v in (s.get("users") or {}).values() for r in v]
    return {r["path"]: r.get("sha256") or "" for r in recs if r.get("path")}


def _m_keys(L):
    k = _d(L, "persistence", "ssh_authorized_keys")
    if k is None:
        return None
    return {f"{a['user']}:{key.get('fingerprint')}": key.get("comment", "") for a in k for key in a.get("keys", []) if key.get("fingerprint")}


def _m_preload(L):
    e = _d(L, "persistence", "misc.ld_so_preload.entries")
    return None if e is None else {x: "" for x in e}


def _m_packages(L):
    p = _d(L, "packages", "packages")
    return None if p is None else {x["name"]: x["version"] for x in p}


def _m_foreign(L):
    p = _d(L, "packages", "packages")
    if p is None or all(x.get("foreign") is None for x in p):
        return None
    return {x["name"]: x["version"] for x in p if x.get("foreign")}


def _m_sysctl(L):
    s = _d(L, "kernel", "sysctl")
    return None if s is None else {k: str(v) for k, v in s.items() if v is not None}


def _m_cmdline(L):
    p = _d(L, "kernel", "cmdline.params")
    return None if p is None else {k: str(v) for k, v in p.items()}


def _m_modules(L):
    m = _d(L, "kernel", "modules.loaded")
    return None if m is None else {x["name"]: "" for x in m}


def _m_ssh(L):
    e = _d(L, "configs", "ssh.effective")
    return None if e is None else {k.lower(): json.dumps(v) for k, v in e.items()}


def _m_sudoers(L):
    s = _d(L, "configs", "sudoers")
    if not s or not s.get("readable"):
        return None
    return {e["raw"]: "" for e in s.get("entries", []) if e.get("type") == "userspec"}


def _m_sudo_defaults(L):
    s = _d(L, "configs", "sudoers")
    if not s or not s.get("readable"):
        return None
    return {k: json.dumps(v) for k, v in (s.get("global_defaults") or {}).items()}


def _m_pam(L):
    p = _d(L, "configs", "pam.files")
    return None if p is None else {n: _h(v.get("entries")) for n, v in p.items()}


def _m_fstab(L):
    f = _d(L, "configs", "fstab.entries")
    return None if f is None else {e["mountpoint"]: f"{e.get('spec')} {e.get('fstype')} {','.join(e.get('options', []))}" for e in f if not e.get("malformed")}


def _m_firewall(L):
    fw = _d(L, "network", "firewall")
    if fw is None:
        return None
    out = {}
    nft = fw.get("nftables")
    if nft:
        out["nftables"] = (f"input chains: " + ";".join(f"{c.get('policy')}/{c.get('rule_count')}" for c in nft.get("base_chains", []) if c.get("hook") == "input")) if nft.get("readable") else "unreadable"
    for t, v in (fw.get("iptables") or {}).items():
        out[t] = f"INPUT={((v.get('policies') or {}).get('INPUT'))} rules={v.get('rule_count')}" if v.get("readable") else "unreadable"
    if fw.get("ufw"):
        out["ufw"] = str(fw["ufw"].get("status"))
    if fw.get("firewalld"):
        out["firewalld"] = str(fw["firewalld"].get("state"))
    return out


MAPS = {
    "suid_sgid": ("filesystem", _m_suid), "listening": ("network", _m_listening), "users": ("accounts", _m_users),
    "privileged_groups": ("accounts", _m_privgroups), "services": ("services", _m_services),
    "timers": ("persistence", _m_timers), "local_units": ("persistence", _m_local_units),
    "cron": ("persistence", _m_cron), "shell_startup": ("persistence", _m_shell),
    "authorized_keys": ("persistence", _m_keys), "ld_preload": ("persistence", _m_preload),
    "packages": ("packages", _m_packages), "foreign_packages": ("packages", _m_foreign),
    "sysctl": ("kernel", _m_sysctl), "kernel_cmdline": ("kernel", _m_cmdline), "modules": ("kernel", _m_modules),
    "ssh_effective": ("configs", _m_ssh), "sudoers": ("configs", _m_sudoers), "sudo_defaults": ("configs", _m_sudo_defaults),
    "pam": ("configs", _m_pam), "fstab": ("configs", _m_fstab), "firewall": ("network", _m_firewall),
}


class NotOneScan(Exception):
    pass


def _ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)


def build_snapshot(out_dir, force: bool = False) -> dict:
    L = load_all(Path(out_dir))
    usable = {n: l for n, l in L.items() if l.usable}
    if not usable:
        raise NotOneScan("no usable collector output (missing, unreadable or older than collector v1.2)")
    stamps = {n: _ts(l.env["timestamp"]) for n, l in usable.items()}
    spread = (max(stamps.values()) - min(stamps.values())).total_seconds() / 60
    if spread > MAX_SCAN_SPREAD_MIN and not force:
        oldest = min(stamps, key=stamps.get)
        raise NotOneScan(f"collector outputs span {spread:.0f} minutes (limit {MAX_SCAN_SPREAD_MIN}; oldest: {oldest}). "
                         "Mixing old and new data would corrupt the history. Re-run all collectors, or use --force.")
    maps, root = {}, {}
    for name, (collector, fn) in MAPS.items():
        try:
            m = fn(L)
        except Exception:
            m = None
        if m is not None:
            maps[name] = {str(k): str(v) for k, v in m.items()}
            root[name] = bool(usable[collector].ran_as_root)
    host = next(iter(usable.values())).env.get("host", "?")
    return {
        "scan_timestamp": max(stamps.values()).isoformat(),
        "host": host,
        "collector_versions": {n: l.env.get("collector_version") for n, l in usable.items()},
        "ran_as_root": {n: bool(l.ran_as_root) for n, l in usable.items()},
        "scan_spread_minutes": round(spread, 1),
        "features": extract(L),
        "maps": maps,
        "map_root": root,
        "collectors_missing": sorted(set(L) - set(usable)),
    }
