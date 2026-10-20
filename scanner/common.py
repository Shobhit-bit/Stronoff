"""Shared helpers for all collectors.

Design rule: collectors report FACTS only. No "this is bad" judgments here --
that is the rule engine's job (Phase 2). Keeping them separate means you can
change a rule without re-scanning, and test rules against saved JSON.
"""
import json
import os
import pwd
import grp
import socket
import stat
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
