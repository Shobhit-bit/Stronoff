#!/usr/bin/env python3
"""Processes collector (Arch Linux first).

Facts per userspace process: identity (pid/ppid/user, real vs effective uid),
the executable (resolved, deleted?, memfd?, owning package), command line
(secrets redacted), cwd, systemd unit, capabilities, seccomp, NoNewPrivs.

Extra: hidden-PID check -- PIDs that answer kill(pid, 0) but are absent from
/proc listings. That is the classic signature of a rootkit hiding from readdir.

SECURITY NOTE: command lines routinely contain secrets (--password=..., tokens,
URLs with credentials). Values are redacted before they reach the JSON.

Usage:
  sudo python -m collectors.processes --out processes.json --pretty
  python -m collectors.processes --no-hidden-check      # skip the PID sweep
  python -m collectors.processes --hash                 # sha256 of each unique exe
"""
import argparse
import os
import pwd
import re
import time
from collections import Counter

import psutil

from .common import new_result, emit, pacman_owners, sha256_file

TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
MAX_CMDLINE_CHARS = 1024

# Linux capability bit -> name (bits 0..40, kernel 5.9+)
CAP_NAMES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
]

SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|api[-_]?key|credential|auth)", re.I)
FLAG_EQ = re.compile(r"^(-{1,2}[\w.-]+)=(.*)$")
URL_CREDS = re.compile(r"(\w+://[^/\s:@]+):([^@\s/]+)@")
# Secrets embedded INSIDE a larger token (e.g. the script string of `sh -c "..."`)
INLINE_FLAG = re.compile(
    r"(-{1,2}[\w.-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key|credential)[\w.-]*(?:=|\s+))(\S+)", re.I)
INLINE_ENV = re.compile(
    r"(\b\w*(?:PASS(?:WORD|WD)?|SECRET|TOKEN|API_?KEY|CREDENTIAL)\w*=)(\S+)", re.I)
MAX_TOKEN_CHARS = 256   # long args are almost always scripts (sh -c, python -c); cap them


def decode_caps(hexstr: str | None) -> list[str]:
    if not hexstr:
        return []
    try:
        val = int(hexstr, 16)
    except ValueError:
        return []
    return [n for i, n in enumerate(CAP_NAMES) if val & (1 << i)]


def redact_cmdline(args: list[str]) -> tuple[str, bool]:
    out, redacted, redact_next = [], False, False
    for a in args:
        if redact_next:
            out.append("<REDACTED>")
            redacted, redact_next = True, False
            continue
        m = FLAG_EQ.match(a)
        if m and SECRET_KEY.search(m.group(1)):
            out.append(f"{m.group(1)}=<REDACTED>")
            redacted = True
            continue
        if a.startswith("-") and SECRET_KEY.search(a) and "=" not in a:
            out.append(a)
            redact_next = True
            continue
        new = URL_CREDS.sub(r"\1:<REDACTED>@", a)
        new = INLINE_FLAG.sub(r"\1<REDACTED>", new)
        new = INLINE_ENV.sub(r"\1<REDACTED>", new)
        if new != a:
            redacted = True
        if len(new) > MAX_TOKEN_CHARS:
            new = new[:MAX_TOKEN_CHARS] + "...[truncated]"
        out.append(new)
    s = " ".join(out)
    return (s[:MAX_CMDLINE_CHARS] + ("...[truncated]" if len(s) > MAX_CMDLINE_CHARS else "")), redacted


_user_cache: dict[int, str | None] = {}


def uname(uid: int) -> str | None:
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _user_cache[uid] = None
    return _user_cache[uid]


def read_status(pid: int) -> dict:
    out = {}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb",
                         "NoNewPrivs", "Seccomp", "Kthread"):
                    out[k] = v.strip()
    except OSError:
        pass
    return out


def read_exe(pid: int) -> dict:
    """Raw readlink so we can see '(deleted)' and memfd (psutil hides/strips these)."""
    try:
        raw = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return {"exe": None, "readable": False, "deleted": None, "memfd": None}
    deleted = raw.endswith(" (deleted)")
    path = raw[:-10] if deleted else raw
    return {"exe": path, "readable": True, "deleted": deleted, "memfd": raw.startswith("/memfd:")}


def read_unit(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            data = f.read()
    except OSError:
        return None
    units = re.findall(r"/([^/\n]+\.(?:service|scope))", data)
    return units[-1] if units else None


def hidden_pid_check(known: set[int]) -> dict:
    """kill(pid, 0) every possible PID; PermissionError still means 'exists'."""
    try:
        with open("/proc/sys/kernel/pid_max") as f:
            pid_max = int(f.read())
    except (OSError, ValueError):
        pid_max = 4194304
    t0 = time.time()
    alive_unknown = []
    for pid in range(1, pid_max + 1):
        if pid in known:
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            pass
        except OSError:
            continue
        alive_unknown.append(pid)

    # Re-verify: short-lived processes (or threads) born during the sweep are not hidden
    confirmed = []
    time.sleep(0.5)
    now_listed = {int(d) for d in os.listdir("/proc") if d.isdigit()}
    for pid in alive_unknown:
        if pid in now_listed:
            continue
        if os.path.isdir(f"/proc/{pid}") is False:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            except PermissionError:
                pass
            confirmed.append(pid)
    return {"performed": True, "pid_max": pid_max,
            "elapsed_seconds": round(time.time() - t0, 1),
            "suspected_hidden_pids": confirmed,
            "note": "Races with short-lived tasks cause occasional false positives; re-run to confirm."}


def collect(do_hidden=True, do_hash=False) -> dict:
    result = new_result("processes")
    if not result["ran_as_root"]:
        result["warnings"].append(
            "Not root: exe/cwd/cmdline of other users' processes are unreadable. Re-run with sudo.")

    attrs = ["pid", "ppid", "name", "status", "create_time", "num_threads",
             "uids", "gids", "cmdline", "cwd"]
    snapshot = list(psutil.process_iter(attrs, ad_value=None))
    names = {p.info["pid"]: p.info["name"] for p in snapshot}

    procs, known_ids, unreadable_exe = [], set(), 0
    for p in snapshot:
        i = p.info
        pid, ppid = i["pid"], i["ppid"]
        known_ids.add(pid)
        try:                                   # thread IDs also occupy the PID space
            known_ids.update(int(t) for t in os.listdir(f"/proc/{pid}/task"))
        except OSError:
            pass

        status = read_status(pid)
        is_kthread = pid == 2 or ppid == 2 or status.get("Kthread") == "1"
        if is_kthread:
            procs.append({"pid": pid, "ppid": ppid, "name": i["name"], "kernel_thread": True})
            continue

        exe = read_exe(pid)
        if not exe["readable"]:
            unreadable_exe += 1
        uids = i["uids"]
        cmd, redacted = redact_cmdline(i["cmdline"] or [])
        cap_eff = status.get("CapEff")
        exe_path = exe["exe"]

        procs.append({
            "pid": pid,
            "ppid": ppid,
            "parent_name": names.get(ppid),
            "name": i["name"],
            "kernel_thread": False,
            "status": i["status"],
            "start_epoch": int(i["create_time"]) if i["create_time"] else None,
            "num_threads": i["num_threads"],
            "user": uname(uids.real) if uids else None,
            "uid_real": uids.real if uids else None,
            "uid_effective": uids.effective if uids else None,
            "uid_saved": uids.saved if uids else None,
            "uid_real_ne_effective": (uids.real != uids.effective) if uids else None,
            "gid_real": i["gids"].real if i["gids"] else None,
            "exe": exe_path,
            "exe_readable": exe["readable"],
            "exe_deleted": exe["deleted"],
            "exe_memfd": exe["memfd"],
            "exe_under_tmp": bool(exe_path and exe_path.startswith(TMP_DIRS)),
            "cmdline": cmd,
            "cmdline_redacted": redacted,
            "cwd": i["cwd"],
            "systemd_unit": read_unit(pid),
            "cap_effective": decode_caps(cap_eff),
            "cap_effective_hex": cap_eff,
            "cap_permitted_hex": status.get("CapPrm"),
            "cap_bounding_hex": status.get("CapBnd"),
            "cap_ambient_hex": status.get("CapAmb"),
            "no_new_privs": status.get("NoNewPrivs") == "1" if "NoNewPrivs" in status else None,
            "seccomp_mode": {"0": "disabled", "1": "strict", "2": "filter"}.get(status.get("Seccomp")),
        })

    # Package ownership (+ optional hash) per UNIQUE exe path, not per process
    exe_paths = sorted({p["exe"] for p in procs
                        if p.get("exe") and not p.get("exe_deleted") and not p.get("exe_memfd")})
    owners = pacman_owners(exe_paths)
    if owners is None:
        result["warnings"].append("pacman not available: package ownership of executables not checked.")
    hashes = {e: sha256_file(e) for e in exe_paths} if do_hash else {}
    for p in procs:
        if p.get("kernel_thread"):
            continue
        e = p["exe"]
        if owners is None or not e or p["exe_deleted"] or p["exe_memfd"]:
            p["package"], p["owned_by_package"] = None, None
        else:
            info = owners.get(e)
            p["package"] = info["package"] if info else None
            p["owned_by_package"] = info is not None
        p["exe_sha256"] = hashes.get(e) if do_hash else None

    hidden = hidden_pid_check(known_ids) if do_hidden else {"performed": False}

    user_procs = [p for p in procs if not p["kernel_thread"]]
    result["data"] = {
        "processes": procs,
        "counts": {
            "total": len(procs),
            "kernel_threads": len(procs) - len(user_procs),
            "userspace": len(user_procs),
            "by_user": dict(Counter(p["user"] for p in user_procs).most_common()),
            "exe_unreadable": unreadable_exe,
            "exe_deleted": sum(bool(p["exe_deleted"]) for p in user_procs),
            "exe_memfd": sum(bool(p["exe_memfd"]) for p in user_procs),
            "exe_under_tmp": sum(p["exe_under_tmp"] for p in user_procs),
            "uid_real_ne_effective": sum(bool(p["uid_real_ne_effective"]) for p in user_procs),
        },
        "hidden_pid_check": hidden,
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect process facts (no judgments).")
    ap.add_argument("--no-hidden-check", action="store_true", help="skip the PID sweep")
    ap.add_argument("--hash", action="store_true", help="sha256 each unique executable")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(not a.no_hidden_check, a.hash), a.out, a.pretty)


if __name__ == "__main__":
    main()
