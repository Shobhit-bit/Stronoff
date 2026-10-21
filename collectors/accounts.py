#!/usr/bin/env python3
"""Accounts collector (Arch Linux first).

Sources:
  /etc/passwd, /etc/shadow (root only), /etc/group, /etc/shells,
  /etc/login.defs, live sessions (psutil), and perms of the account files.

SECURITY NOTE: password hashes are NEVER copied into the output. We only keep
the hash *type* (yescrypt, sha512, ...) and the account state. A scanner report
that contains hashes becomes a credential leak the moment you share it.

Usage:
  python -m collectors.accounts --pretty
  sudo python -m collectors.accounts --out accounts.json   # full coverage
"""
import argparse
import os
import time
from collections import Counter, defaultdict

from .common import new_result, read_lines, file_meta, emit, parse_login_defs

# Groups where membership = elevated power. We report membership as a FACT;
# the rule engine decides what to flag.
PRIVILEGED_GROUPS = {
    "wheel", "sudo", "root", "docker", "podman", "libvirt", "kvm",
    "disk", "adm", "shadow", "systemd-journal", "lxd",
}

NOLOGIN_SUFFIXES = ("nologin", "false")

HASH_PREFIXES = {
    "$y$": "yescrypt",
    "$gy$": "gost-yescrypt",
    "$7$": "scrypt",
    "$6$": "sha512crypt",
    "$5$": "sha256crypt",
    "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt",
    "$1$": "md5crypt",
}

ACCOUNT_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/login.defs", "/etc/shells",
]


def _int_or_none(s: str):
    s = s.strip()
    if s == "":
        return None
    try:
        return int(s)
    except ValueError:
        return None


def classify_hash(field: str) -> dict:
    """Turn the shadow password field into state + algorithm. Hash is discarded."""
    if field == "":
        return {"state": "empty", "algorithm": None}          # login with NO password
    locked = field.startswith("!")
    core = field.lstrip("!")
    if core == "" and locked:
        return {"state": "locked", "algorithm": None}          # '!' alone: locked, no hash
    if core == "*":
        return {"state": "no_password", "algorithm": None}     # '*': password login impossible
    algo = None
    for prefix, name in HASH_PREFIXES.items():
        if core.startswith(prefix):
            algo = name
            break
    if algo is None:
        algo = "des_or_unknown" if "$" not in core else "unknown"
    return {"state": "locked" if locked else "set", "algorithm": algo}


def parse_shadow(result) -> dict:
    """name -> password facts. Empty dict if unreadable."""
    out = {}
    today = int(time.time() // 86400)
    for line in read_lines("/etc/shadow", result):
        f = line.split(":")
        if len(f) < 9:
            result["errors"].append({"path": "/etc/shadow", "error": "malformed_line"})
            continue
        lastchg = _int_or_none(f[2])
        info = classify_hash(f[1])
        info.update({
            "last_change_days_since_epoch": lastchg,
            "days_since_change": (today - lastchg) if lastchg else None,
            "must_change_at_next_login": lastchg == 0,
            "min_days": _int_or_none(f[3]),
            "max_days": _int_or_none(f[4]),
            "warn_days": _int_or_none(f[5]),
            "inactive_days": _int_or_none(f[6]),
            "expire_date_days_since_epoch": _int_or_none(f[7]),
            "account_expired": (_int_or_none(f[7]) is not None and _int_or_none(f[7]) < today),
        })
        out[f[0]] = info
    return out


def parse_groups(result):
    """Returns (gid -> name, name -> gid, user -> [supplementary group names])."""
    gid_to_name, name_to_gid = {}, {}
    members = defaultdict(list)
    for line in read_lines("/etc/group", result):
        f = line.split(":")
        if len(f) < 4:
            result["errors"].append({"path": "/etc/group", "error": "malformed_line"})
            continue
        gid = _int_or_none(f[2])
        gid_to_name[gid] = f[0]
        name_to_gid[f[0]] = gid
        for u in filter(None, f[3].split(",")):
            members[u].append(f[0])
    return gid_to_name, name_to_gid, members


def logged_in_users() -> list[dict]:
    try:
        import psutil
    except ImportError:
        return []
    return [
        {"name": u.name, "terminal": u.terminal, "host": u.host or None,
         "started_epoch": int(u.started)}
        for u in psutil.users()
    ]


def collect() -> dict:
    result = new_result("accounts")
    uid_min = 1000
    login_defs = parse_login_defs(result)
    if "UID_MIN" in login_defs and login_defs["UID_MIN"].isdigit():
        uid_min = int(login_defs["UID_MIN"])

    valid_shells = {
        l.strip() for l in read_lines("/etc/shells", result)
        if l.strip() and not l.startswith("#")
    }
    shadow = parse_shadow(result)
    if not shadow and result["ran_as_root"] is False:
        result["warnings"].append(
            "Not root: /etc/shadow unreadable, password/aging data missing. "
            "Re-run with sudo for full coverage.")

    gid_to_name, _, supp_groups = parse_groups(result)
    sessions = logged_in_users()
    logged_names = {s["name"] for s in sessions}

    users = []
    for line in read_lines("/etc/passwd", result):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) != 7:
            result["errors"].append({"path": "/etc/passwd", "error": "malformed_line",
                                     "line_prefix": line[:20]})
            continue
        name, _, uid_s, gid_s, gecos, home, shell = f
        uid, gid = _int_or_none(uid_s), _int_or_none(gid_s)

        if uid == 0:
            acct_type = "root_uid"
        elif uid == 65534:
            acct_type = "nobody"
        elif uid is not None and uid >= uid_min:
            acct_type = "human"
        else:
            acct_type = "system"

        eff_shell = shell or "/bin/sh"   # empty shell field means /bin/sh
        has_login_shell = (
            eff_shell in valid_shells
            and not eff_shell.endswith(NOLOGIN_SUFFIXES)
        )
        groups = sorted(set(supp_groups.get(name, [])))
        primary = gid_to_name.get(gid)
        all_groups = set(groups) | ({primary} if primary else set())

        users.append({
            "name": name,
            "uid": uid,
            "gid": gid,
            "primary_group": primary,
            "gecos": gecos,
            "home": home,
            "shell": shell,
            "account_type": acct_type,
            "has_login_shell": has_login_shell,
            "supplementary_groups": groups,
            "privileged_groups": sorted(all_groups & PRIVILEGED_GROUPS),
            "home_meta": file_meta(home) if home and home != "/" else None,
            "password": shadow.get(name),      # None if not root / no entry
            "currently_logged_in": name in logged_names,
        })

    # Integrity facts (cheap to compute here, painful to recompute later)
    uid_counts = Counter(u["uid"] for u in users)
    name_counts = Counter(u["name"] for u in users)
    known_gids = set(gid_to_name)
    passwd_names = {u["name"] for u in users}

    result["data"] = {
        "login_defs": {k: login_defs[k] for k in (
            "UID_MIN", "UID_MAX", "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE",
            "ENCRYPT_METHOD", "UMASK", "YESCRYPT_COST_FACTOR", "SHA_CRYPT_MIN_ROUNDS",
        ) if k in login_defs},
        "uid_min_used": uid_min,
        "users": users,
        "sessions": sessions,
        "integrity": {
            "uid0_accounts": [u["name"] for u in users if u["uid"] == 0],
            "duplicate_uids": sorted(k for k, v in uid_counts.items() if v > 1),
            "duplicate_names": sorted(k for k, v in name_counts.items() if v > 1),
            "users_with_unknown_primary_gid": [u["name"] for u in users if u["gid"] not in known_gids],
            "shadow_entries_without_passwd": sorted(set(shadow) - passwd_names),
            "passwd_entries_without_shadow": (sorted(passwd_names - set(shadow)) if shadow else None),
        },
        "privileged_group_members": {
            g: sorted({u["name"] for u in users if g in u["privileged_groups"]})
            for g in sorted(PRIVILEGED_GROUPS)
            if any(g in u["privileged_groups"] for u in users)
        },
        "account_file_meta": [file_meta(p) for p in ACCOUNT_FILES],
        "counts": {
            "total": len(users),
            "human": sum(u["account_type"] == "human" for u in users),
            "system": sum(u["account_type"] == "system" for u in users),
            "with_login_shell": sum(u["has_login_shell"] for u in users),
        },
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect account facts (no judgments).")
    ap.add_argument("--out", help="write JSON to this file instead of stdout")
    ap.add_argument("--pretty", action="store_true", help="indent JSON")
    args = ap.parse_args()
    emit(collect(), args.out, args.pretty)


if __name__ == "__main__":
    main()
