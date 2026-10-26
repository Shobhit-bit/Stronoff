"""Turn one scan (the 10 collector JSONs) into a fixed numeric feature vector.

Design rules:
  * A feature that cannot be measured is None (NaN later) -- NEVER 0. A scan taken without root must
    not look like 'the machine suddenly has no SUID files'.
  * Features are COUNTS and FLAGS of security-relevant structure, not package churn, so a normal
    'pacman -Syu' does not look like an attack.
  * Each feature has a floor on its natural noise (abs_floor / rel_floor) so a constant feature that
    moves by one is not an infinite z-score, while a big jump still is.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable

from engine.config import DEFAULTS
from engine.core import dig


@dataclass(frozen=True)
class Feature:
    name: str
    group: str
    fn: Callable
    abs_floor: float = 1.0       # smallest change that counts as meaningful
    rel_floor: float = 0.0       # extra tolerance as a fraction of the typical value (volatile features)
    kind: str = "structural"     # structural: should be ~constant (low z threshold); volatile: varies daily (high threshold)


def _d(L, collector, path=None):
    """Data of a usable collector (or one of its fields); None if unusable/missing."""
    l = L.get(collector)
    if not l or not l.usable:
        return None
    return l.data if path is None else dig(l.data, path)


def _n(x):
    return len(x) if x is not None else None


def _sum(*vals):
    return None if any(v is None for v in vals) else sum(vals)


def _flag(v):
    return None if v is None else (1.0 if v else 0.0)


def _eff(L, key):
    eff = _d(L, "configs", "ssh.effective")
    if eff is None:
        return None
    v = {k.lower(): x for k, x in eff.items()}.get(key)
    return v[0] if isinstance(v, list) else v


def _count_where(L, collector, path, pred):
    items = _d(L, collector, path)
    return None if items is None else float(sum(1 for i in items if pred(i)))


def _weak_sysctls(L):
    sc = _d(L, "kernel", "sysctl")
    if sc is None:
        return None
    return float(sum(1 for k, bad in DEFAULTS["weak_sysctls"].items() if sc.get(k) == bad))


def _cpu_vuln(L):
    m = _d(L, "kernel", "cpu_mitigations")
    return None if m is None else float(sum(1 for v in m.values() if isinstance(v, str) and v.startswith("Vulnerable")))


def _by_user_root(L):
    b = _d(L, "processes", "counts.by_user")
    return None if b is None else float(b.get("root", 0))


def _persist_keys(L):
    ks = _d(L, "persistence", "ssh_authorized_keys")
    return None if ks is None else float(sum(len(a.get("keys", [])) for a in ks))


def _cron_entries(L):
    c = _d(L, "persistence", "cron")
    if c is None:
        return None
    return float(sum(len(f.get("entries", [])) for k in ("system", "user") for f in c.get(k) or []))


def _est_public(L):
    lst = _d(L, "network", "connections.list")
    return None if lst is None else float(sum(1 for c in lst if c.get("remote_scope") == "public"))


def _fw_filtering(L):
    fw = _d(L, "network", "firewall")
    if fw is None:
        return None
    nft = fw.get("nftables") or {}
    if nft.get("readable") and any(c.get("hook") == "input" and (c.get("policy") == "drop" or c.get("rule_count", 0) > 0)
                                   for c in nft.get("base_chains", [])):
        return 1.0
    for v in (fw.get("iptables") or {}).values():
        if v.get("readable") and ((v.get("policies") or {}).get("INPUT") in ("DROP", "REJECT") or v.get("rule_count", 0) > 0):
            return 1.0
    if (fw.get("ufw") or {}).get("status") == "active" or (fw.get("firewalld") or {}).get("state") == "running":
        return 1.0
    unreadable = any(not (fw.get(k) or {}).get("readable", True) for k in ("nftables", "ufw"))
    return None if unreadable else 0.0


def _altered(L):
    i = _d(L, "packages", "integrity")
    if i is None or not i.get("performed"):
        return None
    return float(sum(1 for f in i.get("altered_files", []) if f.get("content_changed")))


def _empty_pw(L):
    users = _d(L, "accounts", "users")
    if users is None or all(u.get("password") is None for u in users):
        return None
    return float(sum(1 for u in users if (u.get("password") or {}).get("state") == "empty"))


def _priv_members(L):
    p = _d(L, "accounts", "privileged_group_members")
    return None if p is None else float(sum(len(v) for v in p.values()))


def _hidden(L):
    h = _d(L, "processes", "hidden_pid_check")
    return float(len(h.get("suspected_hidden_pids", []))) if h and h.get("performed") else None


def _svc_exposure(L):
    svcs = _d(L, "services", "services")
    if not svcs:
        return None
    vals = [float(s["security_exposure"]) for s in svcs if s.get("sub") == "running" and s.get("security_exposure") is not None]
    return sum(vals) / len(vals) if vals else None


def _svc_unowned_unit(L):
    svcs = _d(L, "services", "services")
    return None if svcs is None else float(sum(1 for s in svcs if s.get("fragment_owned_by_package") is False))


F = Feature
FEATURES: list[Feature] = [
    # accounts
    F("acc_total", "accounts", lambda L: _d(L, "accounts", "counts.total")),
    F("acc_human", "accounts", lambda L: _d(L, "accounts", "counts.human")),
    F("acc_login_shell", "accounts", lambda L: _d(L, "accounts", "counts.with_login_shell")),
    F("acc_uid0", "accounts", lambda L: _n(_d(L, "accounts", "integrity.uid0_accounts")), abs_floor=0.2),
    F("acc_priv_group_members", "accounts", _priv_members),
    F("acc_empty_password", "accounts", _empty_pw, abs_floor=0.2),
    F("acc_logged_in", "accounts", lambda L: _n(_d(L, "accounts", "sessions")), abs_floor=2, kind="volatile"),
    # filesystem
    F("fs_suid", "filesystem", lambda L: _d(L, "filesystem", "totals.suid_files")),
    F("fs_sgid", "filesystem", lambda L: _d(L, "filesystem", "totals.sgid_files")),
    F("fs_suid_unowned", "filesystem", lambda L: _count_where(L, "filesystem", "suid_files", lambda f: f.get("owned_by_package") is False)),
    F("fs_world_writable_files", "filesystem", lambda L: _d(L, "filesystem", "totals.world_writable_files"), abs_floor=3, kind="volatile"),
    F("fs_world_writable_dirs", "filesystem", lambda L: _d(L, "filesystem", "totals.world_writable_dirs_no_sticky"), abs_floor=3, kind="volatile"),
    F("fs_unowned", "filesystem", lambda L: _d(L, "filesystem", "totals.unowned_files"), abs_floor=2, kind="volatile"),
    F("fs_capabilities", "filesystem", lambda L: _n(_d(L, "filesystem", "capabilities"))),
    # processes
    F("proc_userspace", "processes", lambda L: _d(L, "processes", "counts.userspace"), abs_floor=15, rel_floor=0.15, kind="volatile"),
    F("proc_root", "processes", _by_user_root, abs_floor=5, rel_floor=0.15, kind="volatile"),
    F("proc_deleted_exe", "processes", lambda L: _d(L, "processes", "counts.exe_deleted"), abs_floor=4, kind="volatile"),
    F("proc_memfd_exe", "processes", lambda L: _d(L, "processes", "counts.exe_memfd"), abs_floor=0.5),
    F("proc_tmp_exe", "processes", lambda L: _d(L, "processes", "counts.exe_under_tmp"), abs_floor=0.5),
    F("proc_uid_mismatch", "processes", lambda L: _d(L, "processes", "counts.uid_real_ne_effective"), abs_floor=1),
    F("proc_hidden_pids", "processes", _hidden, abs_floor=0.2),
    # services
    F("svc_running", "services", lambda L: _d(L, "services", "counts.services_running"), abs_floor=3, kind="volatile"),
    F("svc_enabled", "services", lambda L: _d(L, "services", "counts.services_enabled"), abs_floor=2),
    F("svc_root_running", "services", lambda L: _d(L, "services", "counts.services_running_as_root"), abs_floor=2, kind="volatile"),
    F("svc_failed", "services", lambda L: _n(_d(L, "services", "failed_units")), abs_floor=2, kind="volatile"),
    F("svc_unowned_unit", "services", _svc_unowned_unit, abs_floor=1),
    F("svc_exposure_mean", "services", _svc_exposure, abs_floor=0.5, kind="volatile"),
    # packages
    F("pkg_installed", "packages", lambda L: _d(L, "packages", "counts.installed"), abs_floor=10, rel_floor=0.03, kind="volatile"),
    F("pkg_foreign", "packages", lambda L: _d(L, "packages", "counts.foreign"), abs_floor=2),
    F("pkg_orphans", "packages", lambda L: _d(L, "packages", "counts.orphans"), abs_floor=3, kind="volatile"),
    F("pkg_unsigned", "packages", lambda L: _d(L, "packages", "counts.unsigned"), abs_floor=2),
    F("pkg_days_since_upgrade", "packages", lambda L: _d(L, "packages", "updates.last_full_upgrade.days_ago"), abs_floor=14, kind="volatile"),
    F("pkg_altered_files", "packages", _altered, abs_floor=0.5),
    F("pkg_repos", "packages", lambda L: _n(_d(L, "packages", "pacman_conf.repos")), abs_floor=0.5),
    # configs
    F("cfg_ssh_root_login", "configs", lambda L: _flag(None if _eff(L, "permitrootlogin") is None else str(_eff(L, "permitrootlogin")).lower() == "yes"), abs_floor=0.2),
    F("cfg_ssh_password_auth", "configs", lambda L: _flag(None if _eff(L, "passwordauthentication") is None else str(_eff(L, "passwordauthentication")).lower() == "yes"), abs_floor=0.2),
    F("cfg_sudo_specs", "configs", lambda L: _d(L, "configs", "sudoers.summary.userspec_count"), abs_floor=1),
    F("cfg_sudo_nopasswd", "configs", lambda L: _n(_d(L, "configs", "sudoers.summary.nopasswd_specs")), abs_floor=0.3),
    F("cfg_sudo_wildcard", "configs", lambda L: _n(_d(L, "configs", "sudoers.summary.wildcard_specs")), abs_floor=0.3),
    F("cfg_pam_nullok_files", "configs", lambda L: _n(_d(L, "configs", "pam.summary.nullok_files")), abs_floor=0.5),
    # network
    F("net_tcp_all_interfaces", "network", lambda L: _d(L, "network", "counts.tcp_all_interfaces"), abs_floor=1),
    F("net_tcp_loopback", "network", lambda L: _d(L, "network", "counts.tcp_loopback_only"), abs_floor=3, kind="volatile"),
    F("net_udp_bound", "network", lambda L: _d(L, "network", "counts.udp_bound"), abs_floor=2, kind="volatile"),
    F("net_established", "network", lambda L: _d(L, "network", "connections.total_remote_tcp"), abs_floor=8, rel_floor=0.5, kind="volatile"),
    F("net_established_public", "network", _est_public, abs_floor=6, rel_floor=0.5, kind="volatile"),
    F("net_promiscuous", "network", lambda L: _d(L, "network", "counts.promiscuous_interfaces"), abs_floor=0.2),
    F("net_firewall_filtering", "network", _fw_filtering, abs_floor=0.2),
    # logs
    F("log_ssh_failed", "logs", lambda L: _d(L, "logs", "events.ssh.failed_total"), abs_floor=25, rel_floor=0.5, kind="volatile"),
    F("log_ssh_sources", "logs", lambda L: _d(L, "logs", "events.ssh.distinct_failed_sources"), abs_floor=5, rel_floor=0.5, kind="volatile"),
    F("log_ssh_accepted", "logs", lambda L: _d(L, "logs", "events.ssh.accepted_total"), abs_floor=3, rel_floor=0.5, kind="volatile"),
    F("log_sudo_commands", "logs", lambda L: _d(L, "logs", "events.sudo.commands_total"), abs_floor=15, rel_floor=0.5, kind="volatile"),
    F("log_account_changes", "logs", lambda L: _d(L, "logs", "events.account_changes.total"), abs_floor=0.5),
    F("log_coredumps", "logs", lambda L: _d(L, "logs", "events.coredumps.total"), abs_floor=2, kind="volatile"),
    # kernel
    F("krn_weak_sysctls", "kernel", _weak_sysctls, abs_floor=0.5),
    F("krn_cpu_vulnerable", "kernel", _cpu_vuln, abs_floor=0.5),
    F("krn_modules_loaded", "kernel", lambda L: _d(L, "kernel", "modules.loaded_count"), abs_floor=8, rel_floor=0.1, kind="volatile"),
    F("krn_aslr_off", "kernel", lambda L: _flag(None if _d(L, "kernel", "sysctl") is None or _d(L, "kernel", "sysctl").get("kernel.randomize_va_space") is None else _d(L, "kernel", "sysctl")["kernel.randomize_va_space"] != 2), abs_floor=0.2),
    F("krn_reboot_needed", "kernel", lambda L: _flag(None if _d(L, "kernel", "reboot_check.running_kernel_modules_on_disk") is None else not _d(L, "kernel", "reboot_check.running_kernel_modules_on_disk")), abs_floor=0.5, kind="volatile"),
    # persistence
    F("per_cron_entries", "persistence", _cron_entries, abs_floor=0.5),
    F("per_local_units", "persistence", lambda L: _n(_d(L, "persistence", "systemd.local_units")), abs_floor=0.3),
    F("per_authorized_keys", "persistence", _persist_keys, abs_floor=0.3),
    F("per_pattern_hits", "persistence", lambda L: _d(L, "persistence", "counts.with_pattern_hits"), abs_floor=1),
    F("per_world_writable", "persistence", lambda L: _d(L, "persistence", "counts.world_writable"), abs_floor=0.5),
    F("per_unowned", "persistence", lambda L: _d(L, "persistence", "counts.unowned_files"), abs_floor=3, kind="volatile"),
    F("per_ld_preload", "persistence", lambda L: _n(_d(L, "persistence", "misc.ld_so_preload.entries")), abs_floor=0.2),
]
FEATURE_NAMES = [f.name for f in FEATURES]
VOLATILE_MASK = [f.kind == "volatile" for f in FEATURES]
BY_NAME = {f.name: f for f in FEATURES}


def extract(loaded: dict) -> dict:
    """{feature name: float | None}. Never raises: a broken extractor yields None for that feature."""
    out = {}
    for f in FEATURES:
        try:
            v = f.fn(loaded)
            out[f.name] = None if v is None else float(v)
        except Exception:
            out[f.name] = None
    return out
