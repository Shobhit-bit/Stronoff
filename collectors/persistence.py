#!/usr/bin/env python3
"""Persistence collector (Arch Linux first). FACTS only.

Where could something silently re-run itself? Collected:
  cron            /etc/crontab, /etc/cron.d, cron.{hourly,daily,weekly,monthly}, /var/spool/cron
  systemd         locally-created units (/etc/systemd/{system,user}, ~/.config/systemd/user),
                  drop-ins, symlinks pointing outside /usr/lib, timer unit-file states
  shell/login     /etc/profile(.d), bashrc/zshrc/..., per-user dotfiles, ~/.config/autostart,
                  Hyprland exec/exec-once lines
  ssh keys        authorized_keys per user: key type, SHA256 fingerprint, comment, forced command/from
  preload         /etc/ld.so.preload, ld.so.conf(.d)
  pacman hooks    /etc/pacman.d/hooks/*.hook
  udev/modules    local udev rules with RUN+=, modules-load.d
Each item gets: permissions, sha256 (where a file), owning package (unowned = locally created),
and `pattern_hits` (named regex matches such as pipe_to_shell, base64_decode, dev_tcp).
Pattern hits are FACTS about the text, not verdicts: `curl | sh` appears in legit installers too.

Usage: sudo python -m collectors.persistence --out persistence.json --pretty
"""
import argparse
import base64
import glob
import hashlib
import os
import pwd
import re
import shutil
import subprocess

from .common import new_result, read_lines, file_meta, emit, pacman_owners, sha256_file
from .processes import redact_cmdline

CAP = 200
PATTERNS = {
    "pipe_to_shell": r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b",
    "base64_decode": r"base64\s+(-d|--decode)",
    "dev_tcp": r"/dev/(tcp|udp)/",
    "netcat_exec": r"\b(nc|ncat|netcat)\b[^\n]*\s-(e|c)\b",
    "ld_preload": r"LD_PRELOAD|ld\.so\.preload",
    "chmod_suid": r"chmod\s+(\+s|u\+s|[0-7]?[4-7][0-7]{3}\b)",
    "runs_from_tmp": r"(/tmp|/dev/shm|/var/tmp)/\S+",
}
PATTERNS_RX = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
KEY_RX = re.compile(r"(?:^|\s)((?:ssh-|ecdsa-|sk-)[\w@.-]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$")
USER_DOTFILES = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
                 ".zprofile", ".zlogin", ".xprofile", ".xinitrc", ".xsessionrc", ".pam_environment",
                 ".config/fish/config.fish"]
UNIT_SUFFIX = (".service", ".timer", ".socket", ".path", ".mount", ".target")


def hits(text: str) -> list[str]:
    return [k for k, rx in PATTERNS_RX.items() if rx.search(text)]


def read_text(path: str, limit=262144) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


class Registry:
    """Collects file records so package ownership is resolved in ONE pacman call."""
    def __init__(self):
        self.recs = []

    def file(self, path: str, kind: str, **extra) -> dict:
        rec = {"kind": kind, **file_meta(path), **extra}
        text = read_text(path) if os.path.isfile(path) else ""
        rec["pattern_hits"] = hits(text)
        rec["sha256"] = sha256_file(path) if os.path.isfile(path) else None
        self.recs.append(rec)
        return rec

    def resolve(self, result):
        paths = sorted({r["path"] for r in self.recs if r.get("exists")})
        owners = pacman_owners(paths)
        if owners is None:
            result["warnings"].append("pacman not available: 'owned_by_package' unknown (locally created vs packaged).")
        for r in self.recs:
            if owners is None or not r.get("exists"):
                r["package"], r["owned_by_package"] = None, None
            else:
                info = owners.get(r["path"])
                r["package"], r["owned_by_package"] = (info["package"] if info else None), info is not None


def human_users():
    out = []
    for p in pwd.getpwall():
        if (p.pw_uid == 0 or p.pw_uid >= 1000) and p.pw_uid != 65534 and os.path.isdir(p.pw_dir) \
                and not p.pw_shell.endswith(("nologin", "false")):
            out.append(p)
    return out


# ---------- cron ----------
def parse_cron(lines, system: bool):
    out = []
    for raw in lines:
        l = raw.strip()
        if not l or l.startswith("#") or re.match(r"^[A-Za-z_]\w*\s*=", l):
            continue
        parts = l.split(None, 6 if system else 5)
        if l.startswith("@"):
            parts = l.split(None, 2 if system else 1)
            sched, rest = parts[0], parts[1:]
        else:
            if len(parts) < (7 if system else 6):
                continue
            sched, rest = " ".join(parts[:5]), parts[5:]
        user = rest[0] if system and rest else None
        cmd = " ".join(rest[1:] if system else rest)
        red, _ = redact_cmdline(cmd.split())
        out.append({"schedule": sched, "user": user, "command": red[:300], "pattern_hits": hits(cmd)})
    return out


def collect_cron(reg, result):
    sec = {"system": [], "user": [], "scripts": []}
    files = ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*"))
    for f in files:
        if os.path.isfile(f):
            sec["system"].append({**reg.file(f, "cron_system"), "entries": parse_cron(read_lines(f, result), True)[:CAP]})
    for d in ("hourly", "daily", "weekly", "monthly"):
        for f in sorted(glob.glob(f"/etc/cron.{d}/*"))[:CAP]:
            if os.path.isfile(f):
                sec["scripts"].append(reg.file(f, f"cron_{d}"))
    for f in sorted(glob.glob("/var/spool/cron/*") + glob.glob("/var/spool/cron/crontabs/*")):
        if os.path.isfile(f):
            sec["user"].append({**reg.file(f, "cron_user", crontab_owner=os.path.basename(f)),
                                "entries": parse_cron(read_lines(f, result), False)[:CAP]})
    sec["cron_daemons"] = {n: bool(shutil.which(n)) for n in ("crond", "cronie", "fcron", "anacron", "atd")}
    return sec


# ---------- systemd ----------
EXEC_RX = re.compile(r"^\s*Exec\w+\s*=\s*[-@:+!|]*\s*(\S+)", re.M)


def collect_systemd(reg, result, users):
    roots = ["/etc/systemd/system", "/etc/systemd/user"] + [os.path.join(u.pw_dir, ".config/systemd/user") for u in users]
    units, odd_links = [], []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root, followlinks=False):
            if dp.count(os.sep) - root.count(os.sep) > 3:
                dns[:] = []
            for fn in fns:
                p = os.path.join(dp, fn)
                if os.path.islink(p):
                    tgt = os.path.realpath(p)
                    if tgt == "/dev/null":
                        continue                                   # masked unit
                    if not tgt.startswith(("/usr/lib/systemd/", "/lib/systemd/", "/etc/systemd/")):
                        odd_links.append({"path": p, "target": tgt})
                elif fn.endswith(UNIT_SUFFIX) or (fn.endswith(".conf") and dp.endswith(".d")):
                    text = read_text(p)
                    rec = reg.file(p, "systemd_unit" if not fn.endswith(".conf") else "systemd_dropin",
                                   exec_paths=sorted(set(EXEC_RX.findall(text)))[:20])
                    units.append(rec)
    timers = []
    if shutil.which("systemctl"):
        rc = subprocess.run(["systemctl", "list-unit-files", "--type=timer", "--no-legend", "--no-pager"],
                            capture_output=True, text=True, env=dict(os.environ, SYSTEMD_COLORS="0"))
        for l in rc.stdout.splitlines():
            f = l.split()
            if len(f) >= 2:
                timers.append({"name": f[0], "state": f[1]})
    return {"local_units": units[:CAP], "symlinks_outside_systemd_dirs": odd_links[:CAP],
            "timer_unit_files": timers, "enabled_timers": [t["name"] for t in timers if t["state"] == "enabled"]}


# ---------- shell / login ----------
def collect_shell(reg, result, users):
    sec = {"system": [], "users": {}}
    for f in ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/environment", "/etc/zsh/zshenv",
              "/etc/zsh/zprofile", "/etc/zsh/zshrc", "/etc/rc.local", "/etc/xprofile"] + sorted(glob.glob("/etc/profile.d/*")) \
            + sorted(glob.glob("/etc/xdg/autostart/*.desktop")):
        if os.path.isfile(f):
            sec["system"].append(reg.file(f, "shell_system"))
    for u in users:
        items = []
        for rel in USER_DOTFILES:
            p = os.path.join(u.pw_dir, rel)
            if os.path.isfile(p):
                items.append(reg.file(p, "dotfile"))
        for p in sorted(glob.glob(os.path.join(u.pw_dir, ".config/autostart/*.desktop"))):
            text = read_text(p)
            items.append(reg.file(p, "xdg_autostart", exec=[redact_cmdline(m.split())[0][:200] for m in re.findall(r"^Exec\s*=\s*(.+)$", text, re.M)]))
        hypr = os.path.join(u.pw_dir, ".config/hypr")
        for p in sorted(set(glob.glob(os.path.join(hypr, "**/*.conf"), recursive=True)))[:30]:
            text = read_text(p)
            ex = [redact_cmdline(m.split())[0][:200] for m in re.findall(r"^\s*exec(?:-once|r)?(?:\s*=\s*)(.+)$", text, re.M)]
            if ex:
                items.append(reg.file(p, "hyprland_exec", exec_lines=ex[:50]))
        sec["users"][u.pw_name] = items[:CAP]
    return sec


# ---------- ssh keys ----------
def parse_authorized_keys(lines):
    keys = []
    for l in lines:
        l = l.strip()
        if not l or l.startswith("#"):
            continue
        m = KEY_RX.search(l)
        if not m:
            keys.append({"parse_error": True})
            continue
        ktype, blob, comment = m.group(1), m.group(2), (m.group(3) or "")
        opts = l[:m.start(1)].strip()
        try:
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")
        except Exception:
            fp = None
        keys.append({"type": ktype, "fingerprint": fp, "comment": comment[:80],
                     "has_options": bool(opts), "forced_command": "command=" in opts,
                     "from_restriction": "from=" in opts, "restrict": "restrict" in opts})
    return keys


def collect_ssh_keys(reg, result, users):
    out = []
    for u in users:
        for name in ("authorized_keys", "authorized_keys2"):
            p = os.path.join(u.pw_dir, ".ssh", name)
            if os.path.isfile(p):
                out.append({"user": u.pw_name, **reg.file(p, "authorized_keys"),
                            "keys": parse_authorized_keys(read_lines(p, result))[:CAP],
                            "ssh_dir_meta": file_meta(os.path.join(u.pw_dir, ".ssh"))})
    return out


# ---------- misc ----------
def collect_misc(reg, result):
    pre = "/etc/ld.so.preload"
    return {
        "ld_so_preload": {**file_meta(pre), "entries": [l.strip() for l in read_lines(pre, result) if l.strip() and not l.startswith("#")]
                          if os.path.exists(pre) else []},
        "ld_so_conf_files": [reg.file(f, "ld_so_conf") for f in ["/etc/ld.so.conf"] + sorted(glob.glob("/etc/ld.so.conf.d/*")) if os.path.isfile(f)],
        "pacman_hooks": [{**reg.file(f, "pacman_hook"),
                          "exec": re.findall(r"^\s*Exec\s*=\s*(.+)$", read_text(f), re.M)[:5],
                          "when": re.findall(r"^\s*When\s*=\s*(.+)$", read_text(f), re.M)[:3]}
                         for f in sorted(glob.glob("/etc/pacman.d/hooks/*.hook"))],
        "udev_rules_local": [{**reg.file(f, "udev_rule"), "has_run_directive": bool(re.search(r"\bRUN\s*\+?=", read_text(f)))}
                             for f in sorted(glob.glob("/etc/udev/rules.d/*.rules")) if not os.path.islink(f)],
        "modules_load_d": [reg.file(f, "modules_load") for f in sorted(glob.glob("/etc/modules-load.d/*.conf"))],
    }


def collect() -> dict:
    result = new_result("persistence")
    if not result["ran_as_root"]:
        result["warnings"].append("Not root: other users' crontabs, homes and /root are unreadable. Re-run with sudo.")
    reg, users = Registry(), human_users()
    sections = {
        "cron": lambda: collect_cron(reg, result),
        "systemd": lambda: collect_systemd(reg, result, users),
        "shell": lambda: collect_shell(reg, result, users),
        "ssh_authorized_keys": lambda: collect_ssh_keys(reg, result, users),
        "misc": lambda: collect_misc(reg, result),
    }
    data = {"users_scanned": [u.pw_name for u in users]}
    for name, fn in sections.items():
        try:
            data[name] = fn()
        except Exception as e:
            data[name] = None
            result["errors"].append({"section": name, "error": f"{type(e).__name__}: {e}"})
    reg.resolve(result)
    data["counts"] = {
        "records": len(reg.recs),
        "unowned_files": sum(r.get("owned_by_package") is False for r in reg.recs),
        "with_pattern_hits": sum(bool(r["pattern_hits"]) for r in reg.recs),
        "world_writable": sum(bool(r.get("world_writable")) for r in reg.recs),
    }
    result["data"] = data
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect persistence-mechanism facts (no judgments).")
    ap.add_argument("--out"); ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(), a.out, a.pretty)


if __name__ == "__main__":
    main()
