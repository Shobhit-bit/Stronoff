#!/usr/bin/env python3
"""Filesystem collector (Arch Linux first).

Collects FACTS about:
  - SUID / SGID regular files (+ sha256 + owning pacman package)
  - World-writable files, and world-writable dirs WITHOUT the sticky bit
  - Files/dirs whose owner UID or GID no longer exists ("unowned")
  - File capabilities (getcap) -- the modern alternative to SUID
  - Mount options for key paths (nosuid/nodev/noexec on /tmp, /home, ...)
  - Permissions of security-sensitive paths

Notes:
  * Symlinks are never followed (avoids loops and escaping the scan root).
  * Pseudo (/proc, /sys...) and network filesystems are pruned automatically.
  * Run as root for full coverage; unreadable dirs are counted, not hidden.
  * Lists are capped (MAX_LIST) so one noisy directory can't blow up the JSON;
    the true total is always recorded and `truncated` tells you if it was cut.

Usage:
  sudo python -m collectors.filesystem --out filesystem.json --pretty
  python -m collectors.filesystem --root /usr --root /etc      # quick test
"""
import argparse
import grp
import hashlib
import os
import pwd
import re
import shutil
import stat
import subprocess
import time

from .common import new_result, read_lines, file_meta, emit, pacman_owners, sha256_file

MAX_LIST = 1000

PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "debugfs", "tracefs", "configfs", "bpf", "pstore", "mqueue", "hugetlbfs",
    "fusectl", "autofs", "binfmt_misc", "efivarfs", "rpc_pipefs", "nsfs",
    "selinuxfs", "fuse.gvfsd-fuse", "fuse.portal", "ramfs",
}
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "afs", "9p", "ceph", "glusterfs"}

# Pruned by default. /.snapshots etc. are duplicates of the real tree (btrfs/snapper).
DEFAULT_EXCLUDES = [
    "/proc", "/sys", "/dev", "/run",
    "/.snapshots", "/var/lib/docker", "/var/lib/containers", "/var/lib/lxc",
]

# World-writable is EXPECTED here, so we don't list it (SUID/SGID still reported).
WW_EXPECTED = ("/tmp", "/var/tmp", "/dev/shm")

KEY_MOUNT_PATHS = ["/", "/boot", "/efi", "/home", "/tmp", "/var", "/var/tmp", "/dev/shm"]

SENSITIVE_PATHS = [
    "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/ssh/sshd_config",
    "/etc/crontab", "/etc/cron.d", "/etc/fstab", "/etc/ld.so.preload",
    "/boot", "/root", "/tmp", "/var/tmp", "/dev/shm", "/var/log",
]


def _unescape_mount(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def parse_mounts(result: dict) -> list[dict]:
    mounts = []
    for line in read_lines("/proc/self/mounts", result):
        f = line.split()
        if len(f) < 4:
            continue
        mounts.append({
            "device": f[0],
            "mountpoint": _unescape_mount(f[1]),
            "fstype": f[2],
            "options": f[3].split(","),
        })
    return mounts


def key_mount_facts(mounts: list[dict]) -> list[dict]:
    """For each key path: which mount covers it and its security-relevant options."""
    out = []
    for p in KEY_MOUNT_PATHS:
        if not os.path.exists(p):
            continue
        covering = max(
            (m for m in mounts if p == m["mountpoint"] or p.startswith(m["mountpoint"].rstrip("/") + "/")),
            key=lambda m: len(m["mountpoint"]), default=None)
        if covering is None:
            continue
        opts = set(covering["options"])
        out.append({
            "path": p,
            "mountpoint": covering["mountpoint"],
            "separate_mount": covering["mountpoint"] == p,
            "fstype": covering["fstype"],
            "options": covering["options"],
            "nosuid": "nosuid" in opts,
            "nodev": "nodev" in opts,
            "noexec": "noexec" in opts,
        })
    return out


def _under(path: str, roots) -> bool:
    return any(path == r or path.startswith(r + "/") for r in roots)


class Accumulator:
    def __init__(self):
        self.lists = {k: [] for k in (
            "suid_files", "sgid_files", "world_writable_files",
            "world_writable_dirs_no_sticky", "unowned_files")}
        self.totals = {k: 0 for k in self.lists}
        self.totals["world_writable_dirs_sticky"] = 0

    def add(self, cat: str, rec: dict):
        self.totals[cat] += 1
        if len(self.lists[cat]) < MAX_LIST:
            self.lists[cat].append(rec)


_uid_cache: dict[int, str | None] = {}
_gid_cache: dict[int, str | None] = {}


def _owner(uid):
    if uid not in _uid_cache:
        try:
            _uid_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_cache[uid] = None
    return _uid_cache[uid]


def _group(gid):
    if gid not in _gid_cache:
        try:
            _gid_cache[gid] = grp.getgrgid(gid).gr_name
        except KeyError:
            _gid_cache[gid] = None
    return _gid_cache[gid]


def _rec(path: str, st: os.stat_result) -> dict:
    return {
        "path": path,
        "mode": format(stat.S_IMODE(st.st_mode), "04o"),
        "uid": st.st_uid, "gid": st.st_gid,
        "owner": _owner(st.st_uid), "group": _group(st.st_gid),
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    }


def walk(roots, skip_paths, acc: Accumulator, stats: dict):
    stack = list(roots)
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except PermissionError:
            stats["denied_dirs"] += 1
            continue
        except OSError:
            stats["unreadable_dirs"] += 1
            continue
        stats["dirs_scanned"] += 1
        with it:
            for e in it:
                path = e.path
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                mode = st.st_mode
                expected_ww = _under(path, WW_EXPECTED)

                # Unowned check applies to everything (files, dirs, symlinks)
                if _owner(st.st_uid) is None or _group(st.st_gid) is None:
                    acc.add("unowned_files", _rec(path, st))

                if stat.S_ISDIR(mode):
                    if path in skip_paths:
                        continue
                    if (mode & stat.S_IWOTH) and not expected_ww:
                        if mode & stat.S_ISVTX:
                            acc.totals["world_writable_dirs_sticky"] += 1
                        else:
                            acc.add("world_writable_dirs_no_sticky", _rec(path, st))
                    stack.append(path)
                elif stat.S_ISREG(mode):
                    stats["files_scanned"] += 1
                    if mode & stat.S_ISUID:
                        acc.add("suid_files", _rec(path, st))
                    if mode & stat.S_ISGID:
                        acc.add("sgid_files", _rec(path, st))
                    if (mode & stat.S_IWOTH) and not expected_ww:
                        acc.add("world_writable_files", _rec(path, st))


def collect_capabilities(roots: list[str]) -> list[dict] | None:
    if not shutil.which("getcap"):
        return None
    targets = [r for r in roots if os.path.isdir(r)]
    if not targets:
        return []
    try:
        p = subprocess.run(["getcap", "-r", *targets], capture_output=True,
                           text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError):
        return None
    caps = []
    for line in p.stdout.splitlines():
        m = re.match(r"^(\S.*?)\s+(?:=\s*)?(cap_\S.*)$", line.strip())
        if m:
            caps.append({"path": m.group(1), "capabilities": m.group(2)})
    return caps


def collect(roots=None, extra_excludes=None, do_hash=True) -> dict:
    result = new_result("filesystem")
    roots = [os.path.abspath(r) for r in (roots or ["/"])]
    excludes = set(DEFAULT_EXCLUDES) | {os.path.abspath(x) for x in (extra_excludes or [])}

    mounts = parse_mounts(result)
    pruned_mounts = sorted({
        m["mountpoint"] for m in mounts
        if (m["fstype"] in PSEUDO_FS or m["fstype"] in NETWORK_FS) and m["mountpoint"] != "/"})
    skip_paths = excludes | set(pruned_mounts)

    if not result["ran_as_root"]:
        result["warnings"].append(
            "Not root: unreadable directories are skipped (see scan.denied_dirs). "
            "Re-run with sudo for full coverage.")

    stats = {"dirs_scanned": 0, "files_scanned": 0, "denied_dirs": 0, "unreadable_dirs": 0}
    acc = Accumulator()
    t0 = time.time()
    walk(roots, skip_paths, acc, stats)
    elapsed = round(time.time() - t0, 1)

    # Enrich SUID/SGID with package ownership + hash
    sp_paths = sorted({r["path"] for r in acc.lists["suid_files"] + acc.lists["sgid_files"]})
    owners = pacman_owners(sp_paths)
    if owners is None:
        result["warnings"].append("pacman not available: package ownership of SUID/SGID files not checked.")
    for rec in acc.lists["suid_files"] + acc.lists["sgid_files"]:
        if owners is None:
            rec["package"] = None
            rec["owned_by_package"] = None
        else:
            info = owners.get(rec["path"])
            rec["package"] = info["package"] if info else None
            rec["owned_by_package"] = info is not None
        rec["sha256"] = sha256_file(rec["path"]) if do_hash else None

    cap_roots = [r for r in ("/usr", "/opt", "/bin", "/sbin", "/usr/local") if os.path.isdir(r)]
    caps = collect_capabilities(cap_roots)

    result["data"] = {
        "scan": {
            "roots": roots,
            "excluded_paths": sorted(excludes),
            "pruned_mountpoints": pruned_mounts,
            "elapsed_seconds": elapsed,
            **stats,
            "list_cap": MAX_LIST,
            "truncated": {k: acc.totals[k] > MAX_LIST for k in acc.lists},
        },
        "totals": acc.totals,
        "mounts": [m for m in mounts if m["fstype"] not in PSEUDO_FS],
        "key_mounts": key_mount_facts(mounts),
        **acc.lists,
        "capabilities": caps,
        "sensitive_paths": [file_meta(p) for p in SENSITIVE_PATHS],
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect filesystem permission facts (no judgments).")
    ap.add_argument("--root", action="append", help="dir to scan (repeatable, default /)")
    ap.add_argument("--exclude", action="append", help="extra path to skip (repeatable)")
    ap.add_argument("--no-hash", action="store_true", help="skip sha256 of SUID/SGID files")
    ap.add_argument("--out", help="write JSON to file")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    emit(collect(args.root, args.exclude, not args.no_hash), args.out, args.pretty)


if __name__ == "__main__":
    main()
