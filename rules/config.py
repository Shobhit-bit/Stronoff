"""Thresholds: every number or list a rule uses lives here (constraint C11). thresholds.yaml overrides."""
from __future__ import annotations
import copy
import os

DEFAULTS = {
    "stale_upgrade_days": {"medium": 30, "high": 90},
    "brute_force_min_failures": 5,
    "min_journal_days": 7,
    "risky_ports": [21, 23, 69, 111, 135, 136, 137, 138, 139, 445, 512, 513, 514, 2049, 2375,
                    3306, 5432, 5900, 5901, 5902, 6379, 9200, 11211, 27017],
    "critical_ports": [2375],
    "user_writable_prefixes": ["/tmp", "/var/tmp", "/dev/shm", "/home", "/run/user"],
    "system_dirs": ["/etc", "/usr", "/boot", "/opt"],
    "package_dirs": ["/usr", "/opt"],
    "critical_account_files": ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"],
    "sensitive_files": ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
                        "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/crontab", "/etc/cron.d",
                        "/etc/fstab", "/boot"],
    "auth_binaries": ["/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/login",
                      "/usr/bin/sshd", "/usr/bin/sshd-session", "/usr/bin/doas", "/usr/bin/pkexec"],
    "auth_prefixes": ["/usr/lib/security/", "/usr/lib/libpam"],
    "dangerous_cmdline_params": ["nokaslr", "nopti", "nospectre_v2", "norandmaps"],
    "weak_sysctls": {
        "kernel.yama.ptrace_scope": 0, "kernel.unprivileged_bpf_disabled": 0,
        "fs.protected_hardlinks": 0, "fs.protected_symlinks": 0, "fs.protected_fifos": 0,
        "fs.protected_regular": 0, "net.ipv4.conf.all.accept_redirects": 1,
        "net.ipv4.conf.all.accept_source_route": 1, "kernel.kptr_restrict": 0,
    },
    "strong_pattern_hits": ["dev_tcp", "netcat_exec", "base64_decode", "pipe_to_shell", "chmod_suid"],
    "sudo_dangerous_env_keep": ["LD_PRELOAD", "LD_LIBRARY_PATH"],
}


def load_thresholds(path: str | None = None) -> dict:
    th = copy.deepcopy(DEFAULTS)
    if path and os.path.exists(path):
        import yaml
        with open(path, encoding="utf-8") as f:
            over = yaml.safe_load(f) or {}
        for k, v in over.items():
            th[k] = v
    return th
