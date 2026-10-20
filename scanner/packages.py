#!/usr/bin/env python3
"""Packages collector (Arch Linux / pacman).

Inventory + package-manager facts. CVE matching is NOT done here: that is Phase 3
(Arch Security Tracker / NVD -> SQLite). This module produces the clean inventory
that Phase 3 will join against.

Collects:
  - every installed package from the local pacman DB (/var/lib/pacman/local/*/desc):
    name, version (split into epoch / upstream / pkgrel), arch, install reason,
    install + build dates, packager, signature validation, url, size
  - foreign packages (`pacman -Qm`: AUR / manually built -> no tracker coverage)
  - orphaned dependencies (`pacman -Qdtq`)
  - pending updates (checkupdates, else `pacman -Qu`) + sync-DB age + last full upgrade
  - /etc/pacman.conf facts: repos, SigLevel, IgnorePkg/IgnoreGroup, ...
  - mirror schemes (https vs http)
  - file-integrity check (`pacman -Qkk`): files that differ from what the package shipped

Usage:
  sudo python -m collectors.packages --out packages.json --pretty
  sudo python -m collectors.packages --no-verify      # skip the slow integrity check
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone

from .common import new_result, read_lines, emit

LOCAL_DB = "/var/lib/pacman/local"
SYNC_DB_DIR = "/var/lib/pacman/sync"
PACMAN_CONF = "/etc/pacman.conf"
MIRRORLIST = "/etc/pacman.d/mirrorlist"
PACMAN_LOG = "/var/log/pacman.log"
MAX_VERIFY_LIST = 500


def run(cmd, timeout=120):
    env = dict(os.environ, LC_ALL="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


# ---------- parsers ----------

def parse_desc(text: str) -> dict[str, list[str]]:
    fields, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^%([A-Z0-9]+)%$", line)
        if m:
            cur = m.group(1)
            fields[cur] = []
        elif line.strip() and cur:
            fields[cur].append(line.strip())
    return fields


def split_version(v: str) -> dict:
    """Arch version = [epoch:]pkgver-pkgrel. pkgver is what NVD/CPE matching needs."""
    m = re.match(r"^(?:(\d+):)?(.+)-([^-]+)$", v)
    if not m:
        return {"epoch": None, "upstream_version": v, "pkgrel": None}
    return {"epoch": int(m.group(1)) if m.group(1) else 0,
            "upstream_version": m.group(2), "pkgrel": m.group(3)}


def _int(lst):
    try:
        return int(lst[0])
    except (IndexError, ValueError, TypeError):
        return None


def read_local_db(db_dir: str, result: dict) -> list[dict]:
    pkgs = []
    for desc in sorted(glob.glob(os.path.join(db_dir, "*", "desc"))):
        try:
            with open(desc, encoding="utf-8", errors="replace") as f:
                d = parse_desc(f.read())
        except OSError as e:
            result["errors"].append({"path": desc, "error": str(e)})
            continue
        name = (d.get("NAME") or [None])[0]
        ver = (d.get("VERSION") or [None])[0]
        if not name or not ver:
            result["errors"].append({"path": desc, "error": "missing NAME/VERSION"})
            continue
        pkgs.append({
            "name": name,
            "version": ver,
            **split_version(ver),
            "pkgbase": (d.get("BASE") or [name])[0],
            "arch": (d.get("ARCH") or [None])[0],
            "install_reason": "dependency" if (d.get("REASON") or ["0"])[0] == "1" else "explicit",
            "install_date": _int(d.get("INSTALLDATE")),
            "build_date": _int(d.get("BUILDDATE")),
            "packager": (d.get("PACKAGER") or [None])[0],
            "validation": d.get("VALIDATION") or [],      # e.g. ['pgp'] or ['none']
            "url": (d.get("URL") or [None])[0],
            "size_bytes": _int(d.get("SIZE")),
            "groups": d.get("GROUPS") or [],
            "foreign": None,                              # filled in below
        })
    return pkgs


def parse_pacman_conf(lines: list[str]) -> dict:
    options: dict[str, list[str]] = {}
    repos: list[dict] = []
    section = None
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            section = m.group(1)
            if section != "options":
                repos.append({"name": section, "sig_level": None, "servers": [], "includes": []})
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if section == "options":
            options.setdefault(key, []).extend(val.split() if key in
                ("IgnorePkg", "IgnoreGroup", "NoUpgrade", "NoExtract", "HoldPkg") else [val])
        elif repos:
            if key == "SigLevel":
                repos[-1]["sig_level"] = val
            elif key == "Server":
                repos[-1]["servers"].append(val)
            elif key == "Include":
                repos[-1]["includes"].append(val)
    return {"options": options, "repos": repos}


def parse_mirrors(lines: list[str]) -> dict:
    urls = [l.split("=", 1)[1].strip() for l in lines
            if re.match(r"^\s*Server\s*=", l)]
    schemes: dict[str, int] = {}
    for u in urls:
        s = u.split("://", 1)[0].lower() if "://" in u else "unknown"
        schemes[s] = schemes.get(s, 0) + 1
    return {"active_mirrors": len(urls), "schemes": schemes,
            "non_https": [u for u in urls if not u.lower().startswith("https://")][:20]}


def parse_verify(text: str) -> dict:
    """Parse `pacman -Qkk` output (stdout+stderr)."""
    rx = re.compile(r"^(warning|error|backup file): (?:(\S+): )?(/.*?) \((.+)\)\s*$")
    altered, missing, backups = [], [], []
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        kind, pkg, path, tail = m.groups()
        reasons = re.findall(r"\(([^)]+)\)", "(" + tail + ")") or [tail]
        reasons = [r for r in re.split(r"\)\(|\), \(|, ", tail)] if len(reasons) == 1 else reasons
        rec = {"package": pkg, "path": path, "reasons": [r.strip("() ") for r in reasons]}
        if any("No such file" in r for r in rec["reasons"]):
            missing.append(rec)
        elif kind == "backup file":
            backups.append(rec)
        else:
            rec["content_changed"] = any(("checksum" in r.lower() or "size" in r.lower())
                                         for r in rec["reasons"])
            altered.append(rec)
    return {"altered": altered, "missing": missing, "backup_files_modified": backups}


def last_full_upgrade(path: str) -> dict:
    last = None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if "[PACMAN] starting full system upgrade" in line:
                    last = line[1:line.index("]")]
    except OSError:
        return {"timestamp": None, "days_ago": None}
    days = None
    if last:
        try:
            dt = datetime.strptime(last, "%Y-%m-%dT%H:%M:%S%z")
            days = round((datetime.now(timezone.utc) - dt).total_seconds() / 86400, 1)
        except ValueError:
            pass
    return {"timestamp": last, "days_ago": days}


# ---------- collection ----------

def collect(do_verify=True, db_dir=LOCAL_DB) -> dict:
    result = new_result("packages")
    if not os.path.isdir(db_dir):
        result["warnings"].append(f"{db_dir} not found: not an Arch/pacman system.")
        result["data"] = {"pacman_available": False}
        return result

    pkgs = read_local_db(db_dir, result)
    data: dict = {"pacman_available": True, "packages": pkgs}

    # --- foreign packages (needs synced DBs to mean anything)
    sync_dbs = glob.glob(os.path.join(SYNC_DB_DIR, "*.db"))
    foreign_names = None
    if shutil.which("pacman") and sync_dbs:
        rc, out, _ = run(["pacman", "-Qm"])
        if rc in (0, 1):
            foreign_names = {l.split()[0] for l in out.splitlines() if l.strip()}
    else:
        result["warnings"].append("No sync databases or no pacman: foreign (AUR) package list unavailable.")
    for p in pkgs:
        p["foreign"] = (p["name"] in foreign_names) if foreign_names is not None else None

    # --- orphans
    orphans = None
    if shutil.which("pacman"):
        rc, out, _ = run(["pacman", "-Qdtq"])
        if rc in (0, 1):
            orphans = [l.strip() for l in out.splitlines() if l.strip()]

    # --- pending updates
    updates = {"method": None, "pending": None}
    if shutil.which("checkupdates"):
        rc, out, _ = run(["checkupdates"], timeout=180)
        if rc in (0, 2):
            updates = {"method": "checkupdates", "pending": [
                dict(zip(("name", "old", "new"), (m.group(1), m.group(2), m.group(3))))
                for m in (re.match(r"^(\S+) (\S+) -> (\S+)$", l) for l in out.splitlines()) if m]}
    if updates["pending"] is None and shutil.which("pacman"):
        rc, out, _ = run(["pacman", "-Qu"])
        if rc in (0, 1):
            updates = {"method": "pacman -Qu (uses last-synced DB; may be stale)", "pending": [
                dict(zip(("name", "old", "new"), (m.group(1), m.group(2), m.group(3))))
                for m in (re.match(r"^(\S+) (\S+) -> (\S+)", l) for l in out.splitlines()) if m]}
    if updates["pending"] is None:
        result["warnings"].append("Could not determine pending updates (install pacman-contrib for checkupdates).")

    now = time.time()
    sync_mtimes = [os.path.getmtime(f) for f in sync_dbs] if sync_dbs else []
    data["updates"] = {
        **updates,
        "sync_db_age_days": round((now - max(sync_mtimes)) / 86400, 1) if sync_mtimes else None,
        "last_full_upgrade": last_full_upgrade(PACMAN_LOG),
    }

    # --- pacman.conf + mirrors
    data["pacman_conf"] = parse_pacman_conf(read_lines(PACMAN_CONF, result))
    data["mirrors"] = parse_mirrors(read_lines(MIRRORLIST, result))

    # --- integrity verification
    if do_verify:
        if not result["ran_as_root"]:
            result["warnings"].append("Not root: skipping `pacman -Qkk` integrity check (needs root).")
            data["integrity"] = {"performed": False}
        else:
            t0 = time.time()
            rc, out, err = run(["pacman", "-Qkk"], timeout=1800)
            v = parse_verify(out + "\n" + err)
            data["integrity"] = {
                "performed": rc in (0, 1),
                "elapsed_seconds": round(time.time() - t0, 1),
                "totals": {k: len(x) for k, x in v.items()},
                "altered_files": v["altered"][:MAX_VERIFY_LIST],
                "missing_files": v["missing"][:MAX_VERIFY_LIST],
                "backup_files_modified": v["backup_files_modified"][:MAX_VERIFY_LIST],
                "truncated": any(len(x) > MAX_VERIFY_LIST for x in v.values()),
                "note": "Modification-time-only mismatches are usually benign; "
                        "content_changed=true (size/checksum) is the strong signal.",
            }
            if rc not in (0, 1):
                result["errors"].append({"cmd": "pacman -Qkk", "error": f"rc={rc} {err.strip()[:150]}"})
    else:
        data["integrity"] = {"performed": False}

    data["orphans"] = orphans
    data["counts"] = {
        "installed": len(pkgs),
        "explicit": sum(p["install_reason"] == "explicit" for p in pkgs),
        "dependency": sum(p["install_reason"] == "dependency" for p in pkgs),
        "foreign": sum(bool(p["foreign"]) for p in pkgs) if foreign_names is not None else None,
        "unsigned": sum(("pgp" not in p["validation"]) for p in pkgs),
        "orphans": len(orphans) if orphans is not None else None,
        "updates_pending": len(updates["pending"]) if updates["pending"] is not None else None,
    }
    result["data"] = data
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect package facts (no judgments).")
    ap.add_argument("--no-verify", action="store_true", help="skip pacman -Qkk integrity check")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(not a.no_verify), a.out, a.pretty)


if __name__ == "__main__":
    main()
