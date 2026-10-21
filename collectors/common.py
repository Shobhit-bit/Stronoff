"""Shared helpers for all collectors.

Design rule: collectors report FACTS only. No "this is bad" judgments here --
that is the rule engine's job (Phase 2). Keeping them separate means you can
change a rule without re-scanning, and test rules against saved JSON.
"""
import hashlib
import ipaddress
import json
import os
import pwd
import grp
import re
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"


def new_result(collector: str) -> dict:
    """Standard envelope every collector returns."""
    return {
        "schema_version": SCHEMA_VERSION,
        "collector": collector,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "ran_as_root": os.geteuid() == 0,
        "errors": [],     # things that failed (permission denied, malformed line)
        "warnings": [],   # things that reduce coverage (e.g. not root)
        "data": {},
    }


def read_lines(path: str, result: dict) -> list[str]:
    """Read a text file; record failure in result instead of crashing."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        result["errors"].append({"path": path, "error": "not_found"})
    except PermissionError:
        result["errors"].append({"path": path, "error": "permission_denied"})
    except OSError as e:
        result["errors"].append({"path": path, "error": str(e)})
    return []


def file_meta(path: str) -> dict:
    """Permission/ownership facts about a path (does not follow symlinks)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"path": path, "exists": False}
    except PermissionError:
        return {"path": path, "exists": None, "error": "permission_denied"}

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = None  # orphaned UID -- itself a useful fact
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = None

    mode = stat.S_IMODE(st.st_mode)
    return {
        "path": path,
        "exists": True,
        "mode": format(mode, "04o"),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "owner": owner,
        "group": group,
        "is_symlink": stat.S_ISLNK(st.st_mode),
        "is_dir": stat.S_ISDIR(st.st_mode),
        "world_readable": bool(mode & stat.S_IROTH),
        "world_writable": bool(mode & stat.S_IWOTH),
        "group_writable": bool(mode & stat.S_IWGRP),
    }


def emit(result: dict, out_path: str | None = None, pretty: bool = True) -> None:
    text = json.dumps(result, indent=2 if pretty else None, sort_keys=False)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[+] wrote {out_path}", file=sys.stderr)
    else:
        print(text)


def sha256_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def pacman_owners(paths: list[str]) -> dict | None:
    """path -> {package, version}. Paths absent from the dict are owned by NO package."""
    if not shutil.which("pacman"):
        return None
    owners = {}
    env = dict(os.environ, LC_ALL="C")
    for i in range(0, len(paths), 100):
        chunk = paths[i:i + 100]
        try:
            p = subprocess.run(["pacman", "-Qo", *chunk], capture_output=True,
                               text=True, env=env, timeout=60)
        except (subprocess.TimeoutExpired, OSError):
            return None
        for line in p.stdout.splitlines():
            m = re.match(r"^(.+) is owned by (\S+) (\S+)$", line)
            if m:
                owners[m.group(1)] = {"package": m.group(2), "version": m.group(3)}
    return owners


def parse_login_defs(result) -> dict:
    wanted = {}
    for line in read_lines("/etc/login.defs", result):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            wanted[parts[0]] = parts[1].strip()
    return wanted


def classify_addr(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_unspecified:
        return "all_interfaces"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link_local"
    if a.is_private:
        return "private"
    return "public"
