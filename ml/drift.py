"""Deterministic drift detection: what changed between two scans?

This is the primary Phase 4 detector. With a handful of scans it is far more useful than any model,
because 'a new SUID file / listener / sudo rule / authorized key appeared' needs no training data.

Rigor rules (they prevent false alarms):
  * A map is compared only if BOTH scans collected it (a missing collector is not 'everything removed').
  * It is skipped if one scan ran as root and the other did not (partial vs full visibility).
  * Severity is a HINT from a table below, not a verdict; direction (hardening vs regression) is not judged.
"""
from __future__ import annotations

SEV_ORDER = ["high", "medium", "low", "info"]

# map -> {change: severity}, plus a 'why' string. Unlisted maps default to low.
DRIFT_TABLE = {
    "suid_sgid":         ({"added": "high", "changed": "high", "removed": "info"}, "SUID/SGID file set or contents changed"),
    "listening":         ({"added": "medium", "changed": "medium", "removed": "info"}, "Listening sockets changed"),
    "users":             ({"added": "high", "changed": "medium", "removed": "low"}, "Accounts changed"),
    "privileged_groups": ({"added": "high", "changed": "high", "removed": "low"}, "Privileged group membership changed"),
    "services":          ({"added": "medium", "changed": "low", "removed": "info"}, "Service units changed"),
    "timers":            ({"added": "medium", "changed": "low", "removed": "info"}, "systemd timers changed"),
    "local_units":       ({"added": "high", "changed": "high", "removed": "info"}, "Locally created systemd unit added or modified"),
    "cron":              ({"added": "high", "changed": "high", "removed": "info"}, "Cron job added or modified"),
    "shell_startup":     ({"added": "medium", "changed": "medium", "removed": "info"}, "Shell/login startup file changed"),
    "authorized_keys":   ({"added": "high", "changed": "medium", "removed": "low"}, "SSH authorized key added"),
    "ld_preload":        ({"added": "high", "changed": "high", "removed": "info"}, "/etc/ld.so.preload changed"),
    "packages":          ({"added": "info", "changed": "info", "removed": "info"}, "Package set changed"),
    "foreign_packages":  ({"added": "medium", "changed": "low", "removed": "info"}, "AUR/manual package changed"),
    "sysctl":            ({"added": "low", "changed": "medium", "removed": "low"}, "Kernel setting changed"),
    "kernel_cmdline":    ({"added": "medium", "changed": "medium", "removed": "medium"}, "Boot parameters changed"),
    "modules":           ({"added": "info", "changed": "info", "removed": "info"}, "Kernel modules changed"),
    "ssh_effective":     ({"added": "medium", "changed": "medium", "removed": "medium"}, "sshd effective setting changed"),
    "sudoers":           ({"added": "high", "changed": "high", "removed": "low"}, "sudo rule changed"),
    "sudo_defaults":     ({"added": "high", "changed": "high", "removed": "medium"}, "sudo Defaults changed"),
    "pam":               ({"added": "high", "changed": "high", "removed": "high"}, "PAM configuration changed"),
    "fstab":             ({"added": "medium", "changed": "medium", "removed": "medium"}, "fstab entry changed"),
    "firewall":          ({"added": "medium", "changed": "medium", "removed": "medium"}, "Firewall state changed"),
}
CRITICAL_SSH_KEYS = {"permitrootlogin", "passwordauthentication", "permitemptypasswords", "pubkeyauthentication", "usepam"}


def _sev(map_name: str, change: str, key: str, old, new) -> tuple[str, str]:
    table, why = DRIFT_TABLE.get(map_name, ({}, f"{map_name} changed"))
    sev = table.get(change, "low")
    if map_name == "listening" and change in ("added", "changed") and "all_interfaces" in str(new):
        sev = "high"
    if map_name == "ssh_effective" and key in CRITICAL_SSH_KEYS:
        sev = "high"
    if map_name == "sysctl" and key == "kernel.randomize_va_space":
        sev = "high"
    return sev, why


def compute_drift(prev: dict, cur: dict) -> dict:
    events, compared, skipped = [], [], []
    for name in sorted(set(prev["maps"]) | set(cur["maps"])):
        if name not in prev["maps"] or name not in cur["maps"]:
            skipped.append({"map": name, "reason": "not collected in both scans"})
            continue
        if prev["map_root"].get(name) != cur["map_root"].get(name):
            skipped.append({"map": name, "reason": "root/non-root mismatch between scans (visibility differs)"})
            continue
        compared.append(name)
        a, b = prev["maps"][name], cur["maps"][name]
        for k in sorted(set(a) | set(b)):
            if k not in a:
                change, old, new = "added", None, b[k]
            elif k not in b:
                change, old, new = "removed", a[k], None
            elif a[k] != b[k]:
                change, old, new = "changed", a[k], b[k]
            else:
                continue
            sev, why = _sev(name, change, k, old, new)
            events.append({"map": name, "change": change, "key": k, "old": old, "new": new, "severity": sev, "why": why})
    events.sort(key=lambda e: (SEV_ORDER.index(e["severity"]), e["map"], e["key"]))
    counts = {s: sum(e["severity"] == s for e in events) for s in SEV_ORDER}
    return {"previous": prev["scan_timestamp"], "current": cur["scan_timestamp"], "compared_maps": compared,
            "skipped_maps": skipped, "counts": counts, "events": events}
