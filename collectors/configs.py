#!/usr/bin/env python3
"""Configs collector (Arch Linux first).

Collects FACTS (no verdicts) about security-relevant configuration:
  ssh      effective sshd config (`sshd -T`), config file + host-key permissions
  sudoers  /etc/sudoers + includes, parsed into Defaults / aliases / user specs
  login    /etc/login.defs (all keys)
  fstab    /etc/fstab entries with nosuid/nodev/noexec/user flags
  pam      /etc/pam.d/* parsed into (type, control, module, args) + faillock/pwquality conf

Each section is collected independently: one failing section never kills the others.

Usage:
  sudo python -m collectors.configs --out configs.json --pretty
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import tempfile

from .common import new_result, read_lines, file_meta, emit, parse_login_defs

MAX_RAW = 300


def run(cmd, timeout=30):
    env = dict(os.environ, LC_ALL="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _kv_add(d: dict, k: str, v: str):
    """Single value -> str; repeated key -> list[str]."""
    if k in d:
        if not isinstance(d[k], list):
            d[k] = [d[k]]
        d[k].append(v)
    else:
        d[k] = v


# ======================= SSH =======================

def parse_sshd_T(text: str) -> dict:
    out: dict = {}
    for line in text.splitlines():
        k, _, v = line.strip().partition(" ")
        if k:
            _kv_add(out, k.lower(), v.strip())
    return out


def collect_ssh(result: dict) -> dict:
    sshd = shutil.which("sshd") or ("/usr/bin/sshd" if os.path.exists("/usr/bin/sshd") else None)
    if not sshd:
        return {"installed": False}
    sec: dict = {"installed": True, "effective": None}
    sec["host_keys_present"] = bool(glob.glob("/etc/ssh/ssh_host_*_key"))
    rc, out, err = run([sshd, "-T"])
    if rc != 0 and "no hostkeys available" in err and shutil.which("ssh-keygen"):
        # sshd has never started here, so no host keys exist. Use a throw-away key so we can
        # still read the effective config (nothing is written under /etc/ssh).
        with tempfile.TemporaryDirectory() as td:
            key = os.path.join(td, "k")
            if run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])[0] == 0:
                rc, out, err = run([sshd, "-T", "-h", key])
                if rc == 0:
                    sec["hostkey_substituted"] = True
    if rc == 0:
        sec["effective"] = parse_sshd_T(out)
        sec["effective"].pop("hostkey", None)      # would show the temp key path
    else:
        sec["effective_error"] = err.strip()[:200]
        result["warnings"].append(
            "sshd -T failed (needs root + readable host keys): effective SSH settings MISSING.")

    files = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
    sec["config_files"] = [file_meta(f) for f in files]
    match_blocks = 0
    for f in files:
        if os.path.isfile(f):
            match_blocks += sum(1 for l in read_lines(f, result) if re.match(r"^\s*Match\s", l, re.I))
    sec["match_blocks"] = match_blocks
    sec["host_private_keys"] = [file_meta(f) for f in sorted(glob.glob("/etc/ssh/ssh_host_*_key"))]
    return sec


# ======================= sudoers =======================

DEFAULTS_RX = re.compile(r"^Defaults(?P<scope>[:@!>]\S*)?\s+(?P<rest>.+)$")
ALIAS_RX = re.compile(r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(.+)$")
INCLUDE_RX = re.compile(r"^[#@](include|includedir)\s+(\S+)")
TAG_RX = re.compile(r"\b(NOPASSWD|PASSWD|SETENV|NOSETENV|NOEXEC|EXEC|LOG_INPUT|LOG_OUTPUT)\s*:")


def logical_lines(raw: list[str]):
    buf, start = "", None
    for n, line in enumerate(raw, 1):
        if start is None:
            start = n
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        yield start, (buf + line).strip()
        buf, start = "", None
    if buf:
        yield start, buf.strip()


def parse_defaults_settings(rest: str) -> dict:
    out = {}
    for tok in re.findall(r'(?:[^,"]|"[^"]*")+', rest):
        tok = tok.strip()
        if not tok:
            continue
        if tok.startswith("!"):
            out[tok[1:]] = False
        elif "=" in tok:
            name, _, val = tok.partition("=")
            out[name.rstrip("+-").strip()] = val.strip().strip('"')
        else:
            out[tok] = True
    return out


def parse_userspec(line: str) -> dict | None:
    left, sep, right = line.partition("=")
    if not sep:
        return None
    parts = left.rstrip().rsplit(None, 1)
    if len(parts) != 2:
        return None
    who, hosts = parts
    runas_m = re.search(r"\(([^)]*)\)", right)
    runas = runas_m.group(1).strip() if runas_m else None
    tags = sorted(set(TAG_RX.findall(right)))
    cmds = re.sub(r"\([^)]*\)", "", right)
    cmds = TAG_RX.sub("", cmds)
    tokens = [t.strip() for t in cmds.split(",") if t.strip()]
    return {
        "who": [w.strip() for w in who.split(",") if w.strip()],
        "hosts": [h.strip() for h in hosts.split(",") if h.strip()],
        "runas": runas,
        "tags": tags,
        "nopasswd": "NOPASSWD" in tags,
        "runas_all": bool(runas and "ALL" in re.split(r"[:,\s]+", runas.upper())),
        "runs_all_commands": any(t == "ALL" for t in tokens),
        "has_wildcard_command": any("*" in t for t in tokens),
        "commands": tokens[:20],
    }


def parse_sudoers(raw: list[str], path: str) -> list[dict]:
    entries = []
    for lineno, line in logical_lines(raw):
        if not line:
            continue
        base = {"file": path, "line": lineno, "raw": line[:MAX_RAW]}
        m = INCLUDE_RX.match(line)
        if m:
            entries.append({**base, "type": "include" if m.group(1) == "include" else "includedir",
                            "target": m.group(2)})
            continue
        if line.startswith("#"):
            # '#1000 ALL=...' is a UID user spec, otherwise a comment
            if not re.match(r"^#\d+\s", line):
                continue
        m = DEFAULTS_RX.match(line)
        if m:
            scope = m.group("scope")
            entries.append({**base, "type": "defaults", "scope": scope or "global",
                            "settings": parse_defaults_settings(m.group("rest"))})
            continue
        if ALIAS_RX.match(line):
            entries.append({**base, "type": "alias"})
            continue
        spec = parse_userspec(line)
        if spec:
            entries.append({**base, "type": "userspec", **spec})
        else:
            entries.append({**base, "type": "unparsed"})
    return entries


def collect_sudoers(result: dict) -> dict:
    main = "/etc/sudoers"
    if not shutil.which("sudo") and not os.path.exists(main):
        return {"installed": False}
    sec: dict = {"installed": True, "readable": False, "files": [], "ignored_files": [], "entries": []}
    seen: set[str] = set()

    def process(path: str, depth: int):
        if depth > 5 or path in seen:
            return
        seen.add(path)
        errs_before = len(result["errors"])
        lines = read_lines(path, result)
        if len(result["errors"]) > errs_before and not lines:
            return
        sec["files"].append(file_meta(path))
        entries = parse_sudoers(lines, path)
        sec["entries"].extend(entries)
        for e in entries:
            if e["type"] == "include":
                process(e["target"], depth + 1)
            elif e["type"] == "includedir" and os.path.isdir(e["target"]):
                for name in sorted(os.listdir(e["target"])):
                    full = os.path.join(e["target"], name)
                    if "." in name or name.endswith("~"):       # sudo silently skips these
                        sec["ignored_files"].append(full)
                    elif os.path.isfile(full):
                        process(full, depth + 1)

    process(main, 0)
    sec["readable"] = bool(sec["files"])
    if not sec["readable"]:
        result["warnings"].append("Cannot read /etc/sudoers (needs root): sudo configuration MISSING.")
        return sec

    dflags: dict = {}
    for e in sec["entries"]:
        if e["type"] == "defaults" and e["scope"] == "global":
            dflags.update(e["settings"])
    specs = [e for e in sec["entries"] if e["type"] == "userspec"]
    sec["global_defaults"] = dflags
    sec["summary"] = {
        "userspec_count": len(specs),
        "nopasswd_specs": [e["raw"] for e in specs if e["nopasswd"]],
        "run_all_specs": [e["raw"] for e in specs if e["runs_all_commands"] and e["runas_all"]],
        "wildcard_specs": [e["raw"] for e in specs if e["has_wildcard_command"]],
        "unparsed_lines": sum(e["type"] == "unparsed" for e in sec["entries"]),
    }
    rc, out, err = run(["visudo", "-c"])
    sec["syntax_check"] = {"performed": rc != 127, "ok": rc == 0 if rc != 127 else None,
                           "output": (out + err).strip()[:300]}
    sec["note"] = "Heuristic parse. Cross-check with `sudo -ll` before trusting a finding."
    return sec


# ======================= fstab =======================

def parse_fstab(lines: list[str]) -> list[dict]:
    out = []
    for n, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if len(f) < 4:
            out.append({"line": n, "raw": raw[:MAX_RAW], "malformed": True})
            continue
        opts = f[3].split(",")
        out.append({
            "line": n, "spec": f[0], "mountpoint": f[1], "fstype": f[2], "options": opts,
            "dump": f[4] if len(f) > 4 else None, "pass": f[5] if len(f) > 5 else None,
            "nosuid": "nosuid" in opts, "nodev": "nodev" in opts, "noexec": "noexec" in opts,
            "readonly": "ro" in opts,
            "user_mountable": any(o in ("user", "users", "owner") for o in opts),
            "is_swap": f[2] == "swap",
        })
    return out


# ======================= PAM =======================

PAM_RX = re.compile(r"^(-?\w+)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$")


def parse_pam(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = PAM_RX.match(line)
        if m:
            out.append({"type": m.group(1).lstrip("-"), "control": m.group(2),
                        "module": m.group(3), "args": m.group(4).split()})
    return out


def parse_keyval_conf(path: str, result: dict) -> dict | None:
    if not os.path.isfile(path):
        return None
    out = {}
    for line in read_lines(path, result):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        k, sep, v = line.partition("=")
        out[k.strip()] = v.strip() if sep else True
    return out


def collect_pam(result: dict) -> dict:
    if not os.path.isdir("/etc/pam.d"):
        return {"installed": False}
    files = {}
    for path in sorted(glob.glob("/etc/pam.d/*")):
        if os.path.isfile(path):
            files[os.path.basename(path)] = {"meta": file_meta(path),
                                             "entries": parse_pam(read_lines(path, result))}

    def mod(name): return [(f, e) for f, d in files.items() for e in d["entries"]
                           if e["module"].split("/")[-1] == name]
    summary = {
        "nullok_files": sorted({f for f, e in mod("pam_unix.so") if "nullok" in e["args"] or "nullok_secure" in e["args"]}),
        "pam_faillock_files": sorted({f for f, _ in mod("pam_faillock.so")}),
        "pam_pwquality_files": sorted({f for f, _ in mod("pam_pwquality.so")} | {f for f, _ in mod("pam_cracklib.so")}),
        "pam_wheel_files": sorted({f for f, _ in mod("pam_wheel.so")}),
        "auth_pam_permit": [{"file": f, "control": e["control"]} for f, e in mod("pam_permit.so") if e["type"] == "auth"],
    }
    return {
        "installed": True,
        "files": files,
        "summary": summary,
        "faillock_conf": parse_keyval_conf("/etc/security/faillock.conf", result),
        "pwquality_conf": parse_keyval_conf("/etc/security/pwquality.conf", result),
        "pam_dir_meta": file_meta("/etc/pam.d"),
    }


# ======================= main =======================

def collect() -> dict:
    result = new_result("configs")
    if not result["ran_as_root"]:
        result["warnings"].append("Not root: sshd -T and /etc/sudoers are unreadable. Re-run with sudo.")
    sections = {
        "ssh": lambda: collect_ssh(result),
        "sudoers": lambda: collect_sudoers(result),
        "login_defs": lambda: {"values": parse_login_defs(result), "meta": file_meta("/etc/login.defs")},
        "fstab": lambda: {"entries": parse_fstab(read_lines("/etc/fstab", result)), "meta": file_meta("/etc/fstab")},
        "pam": lambda: collect_pam(result),
    }
    data = {}
    for name, fn in sections.items():
        try:
            data[name] = fn()
        except Exception as e:           # one bad section must not kill the report
            data[name] = None
            result["errors"].append({"section": name, "error": f"{type(e).__name__}: {e}"})
    result["data"] = data
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect config facts (no judgments).")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(), a.out, a.pretty)


if __name__ == "__main__":
    main()
