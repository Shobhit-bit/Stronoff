#!/usr/bin/env python3
"""Logs collector (Arch Linux / systemd journal).

Two parts, FACTS only:

A. Logging infrastructure -- is evidence even being kept?
   journald storage/retention, journal size + time span, auditd status/rule count,
   syslog daemons, permissions of key log files, free space where logs live.

B. Aggregated auth/security events from the journal (default: last 7 days)
   ssh      failed/invalid/accepted logins, top attacking sources, top guessed usernames
   sudo     who ran what (command name only, NEVER arguments), failures
   su       successes/failures
   login    failed console logins
   accounts useradd/usermod/passwd/... events
   crashes  systemd-coredump counts per process (crashing network daemons matter)

The journal is STREAMED line by line and aggregated in memory -- an internet-facing
sshd can produce millions of lines, so nothing is ever loaded wholesale.

SECURITY NOTES
  * Usernames/IPs come from ATTACKERS (log injection is real): every value is stripped
    of control characters and truncated before it is stored.
  * sudo command ARGUMENTS are dropped (they carry secrets); only the program path is kept.
  * The JSON contains source IPs and usernames: treat it as sensitive.

Usage:
  sudo python -m collectors.logs --out logs.json --pretty
  sudo python -m collectors.logs --days 30
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter

from .common import new_result, read_lines, file_meta, emit, classify_addr

AUTH_IDENTIFIERS = [
    "sshd", "sshd-session", "sudo", "su", "login",
    "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel",
    "passwd", "chage", "chpasswd", "newusers", "gpasswd", "chsh", "chfn",
    "systemd-coredump",
]
ACCOUNT_TOOLS = set(AUTH_IDENTIFIERS[6:-1]) | {"useradd", "usermod", "userdel"}
TOP_N = 20
MAX_KEYS = 200_000          # cap on distinct attacker IPs/usernames kept in memory
MAX_EVENTS = 200
LOG_FILES = [
    "/var/log/journal", "/var/log/btmp", "/var/log/wtmp", "/var/log/lastlog",
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
    "/var/log/pacman.log", "/var/log/audit/audit.log",
]


def run(cmd, timeout=30):
    env = dict(os.environ, LC_ALL="C", SYSTEMD_COLORS="0", SYSTEMD_PAGER="")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def sanitize(s: str, n: int = 64) -> str:
    """Attacker-controlled text: strip control/non-ASCII, cap length."""
    return re.sub(r"[^\x20-\x7e]", "?", s)[:n]


# ====================== B. event aggregation ======================

SSH_FAILED = re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port \d+")
SSH_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
SSH_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+")
SSH_PREAUTH = re.compile(r"(?:Connection closed by|Disconnected from) authenticating user (\S+) (\S+) port")
SSH_NOISE = re.compile(r"Did not receive identification string|Bad protocol version identification|"
                       r"Unable to negotiate|kex_exchange_identification|banner exchange")
SSH_MAXAUTH = re.compile(r"maximum authentication attempts exceeded|Too many authentication failures")
SUDO_LINE = re.compile(r"^\s*(\S+) : (.*)$")
SUDO_USER = re.compile(r"USER=(\S+)")
SUDO_CMD = re.compile(r"COMMAND=(\S+)")
SUDO_PAM_FAIL = re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?\buser=(\S+)")
SU_OK = re.compile(r"^\(to (\S+)\) (\S+) on")
SU_FAIL = re.compile(r"FAILED SU \(to (\S+)\) (\S+) on")
LOGIN_FAIL = re.compile(r"FAILED LOGIN")
COREDUMP = re.compile(r"Process \d+ \((.+?)\) of user (\d+) dumped core")


class Aggregator:
    def __init__(self):
        self.lines = 0
        self.first = None
        self.last = None
        self.dropped_keys = 0
        # ssh
        self.ssh_failed = 0
        self.ssh_failed_methods = Counter()
        self.ssh_invalid = 0
        self.ssh_failed_src = Counter()
        self.ssh_users = Counter()
        self.ssh_accepted = {}            # (user, method, ip) -> [count, last_epoch]
        self.ssh_accepted_total = 0
        self.ssh_preauth = 0
        self.ssh_noise = 0
        self.ssh_maxauth = 0
        # sudo
        self.sudo_total = 0
        self.sudo_by_user = Counter()
        self.sudo_cmds = Counter()
        self.sudo_runas = Counter()
        self.sudo_not_in_sudoers = Counter()
        self.sudo_bad_password = Counter()
        self.sudo_auth_fail = Counter()
        # su
        self.su_ok = Counter()
        self.su_fail = Counter()
        # misc
        self.login_fail = 0
        self.account_events = []
        self.account_events_total = 0
        self.coredumps = Counter()

    def _bump(self, counter: Counter, key: str):
        if key in counter or len(counter) < MAX_KEYS:
            counter[key] += 1
        else:
            self.dropped_keys += 1

    def feed(self, rec: dict):
        msg, ident = rec.get("MESSAGE"), rec.get("SYSLOG_IDENTIFIER")
        if not isinstance(msg, str) or not ident:
            return
        try:
            ts = int(rec["__REALTIME_TIMESTAMP"]) / 1e6
        except (KeyError, ValueError, TypeError):
            ts = None
        self.lines += 1
        if ts:
            self.first = ts if self.first is None else min(self.first, ts)
            self.last = ts if self.last is None else max(self.last, ts)

        if ident in ("sshd", "sshd-session"):
            m = SSH_FAILED.search(msg)
            if m:
                self.ssh_failed += 1
                self.ssh_failed_methods[sanitize(m.group(1), 32)] += 1
                self._bump(self.ssh_failed_src, sanitize(m.group(3), 45))
                self._bump(self.ssh_users, sanitize(m.group(2)))
                return
            m = SSH_INVALID.search(msg)
            if m:
                self.ssh_invalid += 1
                self._bump(self.ssh_users, sanitize(m.group(1)))
                self._bump(self.ssh_failed_src, sanitize(m.group(2), 45))
                return
            m = SSH_ACCEPTED.search(msg)
            if m:
                self.ssh_accepted_total += 1
                key = (sanitize(m.group(2)), sanitize(m.group(1), 32), sanitize(m.group(3), 45))
                if key in self.ssh_accepted or len(self.ssh_accepted) < 500:
                    ent = self.ssh_accepted.setdefault(key, [0, 0])
                    ent[0] += 1
                    ent[1] = max(ent[1], ts or 0)
                return
            if SSH_PREAUTH.search(msg):
                self.ssh_preauth += 1
            elif SSH_NOISE.search(msg):
                self.ssh_noise += 1
            elif SSH_MAXAUTH.search(msg):
                self.ssh_maxauth += 1

        elif ident == "sudo":
            m = SUDO_PAM_FAIL.search(msg)
            if m:
                self._bump(self.sudo_auth_fail, sanitize(m.group(1)))
                return
            m = SUDO_LINE.match(msg)
            if not m:
                return
            user, rest = sanitize(m.group(1)), m.group(2)
            if "NOT in sudoers" in rest:
                self._bump(self.sudo_not_in_sudoers, user)
            elif "incorrect password attempt" in rest:
                self._bump(self.sudo_bad_password, user)
            elif "COMMAND=" in rest:
                self.sudo_total += 1
                self._bump(self.sudo_by_user, user)
                cmd = SUDO_CMD.search(rest)
                if cmd:                       # program only, arguments dropped on purpose
                    self._bump(self.sudo_cmds, sanitize(cmd.group(1), 120))
                ru = SUDO_USER.search(rest)
                if ru:
                    self._bump(self.sudo_runas, sanitize(ru.group(1)))

        elif ident == "su":
            m = SU_FAIL.search(msg)
            if m:
                self._bump(self.su_fail, f"{sanitize(m.group(2))}->{sanitize(m.group(1))}")
                return
            m = SU_OK.match(msg)
            if m:
                self._bump(self.su_ok, f"{sanitize(m.group(2))}->{sanitize(m.group(1))}")

        elif ident == "login":
            if LOGIN_FAIL.search(msg):
                self.login_fail += 1

        elif ident == "systemd-coredump":
            m = COREDUMP.search(msg)
            if m:
                self._bump(self.coredumps, sanitize(m.group(1), 64))

        elif ident in ACCOUNT_TOOLS:
            self.account_events_total += 1
            if len(self.account_events) < MAX_EVENTS:
                self.account_events.append({"epoch": int(ts) if ts else None, "tool": ident,
                                            "message": sanitize(msg, 200)})

    def _top(self, c: Counter, with_scope=False):
        out = []
        for k, v in c.most_common(TOP_N):
            e = {"value": k, "count": v}
            if with_scope:
                e["scope"] = classify_addr(k)
            out.append(e)
        return out

    def result(self) -> dict:
        accepted = [{"user": u, "method": m, "source": ip, "scope": classify_addr(ip),
                     "count": c, "last_seen_epoch": int(t) or None}
                    for (u, m, ip), (c, t) in sorted(self.ssh_accepted.items(), key=lambda kv: -kv[1][0])[:100]]
        return {
            "journal_lines_processed": self.lines,
            "first_event_epoch": int(self.first) if self.first else None,
            "last_event_epoch": int(self.last) if self.last else None,
            "distinct_keys_dropped_over_cap": self.dropped_keys,
            "ssh": {
                "failed_total": self.ssh_failed,
                "failed_by_method": dict(self.ssh_failed_methods),
                "invalid_user_total": self.ssh_invalid,
                "accepted_total": self.ssh_accepted_total,
                "accepted_root_logins": sum(a["count"] for a in accepted if a["user"] == "root"),
                "top_failed_sources": self._top(self.ssh_failed_src, True),
                "distinct_failed_sources": len(self.ssh_failed_src),
                "top_attempted_usernames": self._top(self.ssh_users),
                "accepted": accepted,
                "preauth_disconnects": self.ssh_preauth,
                "scanner_noise_events": self.ssh_noise,
                "max_auth_exceeded": self.ssh_maxauth,
            },
            "sudo": {
                "commands_total": self.sudo_total,
                "by_user": dict(self.sudo_by_user.most_common(TOP_N)),
                "run_as": dict(self.sudo_runas.most_common(TOP_N)),
                "top_commands": self._top(self.sudo_cmds),
                "not_in_sudoers": dict(self.sudo_not_in_sudoers.most_common(TOP_N)),
                "incorrect_password": dict(self.sudo_bad_password.most_common(TOP_N)),
                "pam_auth_failures": dict(self.sudo_auth_fail.most_common(TOP_N)),
            },
            "su": {"success": dict(self.su_ok.most_common(TOP_N)),
                   "failed": dict(self.su_fail.most_common(TOP_N))},
            "console_login_failures": self.login_fail,
            "account_changes": {"total": self.account_events_total, "events": self.account_events},
            "coredumps": {"total": sum(self.coredumps.values()),
                          "by_process": self._top(self.coredumps)},
        }


def stream_journal(args: list[str], max_lines: int | None = None):
    """Yield JSON lines from journalctl; returns (generator, stderr_getter)."""
    errf = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    cmd = ["journalctl", "--no-pager", "-q", "-o", "json", *args]
    env = dict(os.environ, LC_ALL="C", SYSTEMD_COLORS="0", SYSTEMD_PAGER="")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, text=True,
                            encoding="utf-8", errors="replace", env=env)
    state = {"truncated": False}

    def gen():
        n = 0
        try:
            for line in proc.stdout:
                yield line
                n += 1
                if max_lines and n >= max_lines:
                    state["truncated"] = True
                    proc.kill()
                    break
        finally:
            proc.stdout.close()
            proc.wait()

    def stderr():
        errf.seek(0)
        return errf.read()
    return gen(), stderr, state


def journal_bounds() -> dict:
    """Oldest and newest journal entry timestamps (oldest = first streamed line, then kill)."""
    out = {"oldest_epoch": None, "newest_epoch": None}
    for key, extra, in (("oldest_epoch", []), ("newest_epoch", ["-n", "1"])):
        g, _, _ = stream_journal(extra, max_lines=1)
        for line in g:
            try:
                out[key] = int(int(json.loads(line)["__REALTIME_TIMESTAMP"]) / 1e6)
            except (ValueError, KeyError, json.JSONDecodeError):
                pass
            break
    return out


# ====================== A. infrastructure ======================

def _ini_kv(text: str) -> dict:
    out, sect = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            sect = line.strip("[]")
        elif sect == "Journal" and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def parse_size(text: str) -> int | None:
    m = re.search(r"take up ([\d.]+)([KMGT]?)", text)
    if not m:
        return None
    mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}[m.group(2)]
    return int(float(m.group(1)) * mult)


def parse_auditctl_s(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if k and v.strip():
            out[k] = v.strip()
    return out


def collect_infrastructure(result: dict) -> dict:
    infra: dict = {"journalctl_present": bool(shutil.which("journalctl"))}

    # journald effective config
    cfg_text = ""
    if shutil.which("systemd-analyze"):
        rc, out, _ = run(["systemd-analyze", "cat-config", "systemd/journald.conf"])
        cfg_text = out if rc == 0 else ""
    if not cfg_text:
        cfg_text = "\n".join(read_lines("/etc/systemd/journald.conf", result))
    infra["journald_config"] = {k: v for k, v in _ini_kv(cfg_text).items() if k in (
        "Storage", "Compress", "Seal", "SystemMaxUse", "SystemKeepFree", "MaxRetentionSec",
        "ForwardToSyslog", "ForwardToKMsg", "ForwardToConsole", "RateLimitIntervalSec",
        "RateLimitBurst", "SystemMaxFileSize")}
    infra["persistent_journal_dir_exists"] = os.path.isdir("/var/log/journal")

    if infra["journalctl_present"]:
        rc, out, _ = run(["journalctl", "--disk-usage"])
        infra["journal_disk_usage_bytes"] = parse_size(out) if rc == 0 else None
        infra["journal_span"] = journal_bounds()

    # auditd
    audit = {"installed": bool(shutil.which("auditctl"))}
    if audit["installed"]:
        rc, out, err = run(["auditctl", "-s"])
        if rc == 0:
            audit["status"] = parse_auditctl_s(out)
            rc2, out2, _ = run(["auditctl", "-l"])
            audit["rule_count"] = 0 if "No rules" in out2 else len([l for l in out2.splitlines() if l.strip()])
        else:
            audit["status_error"] = (err or out).strip()[:150]
        audit["auditd_service_active"] = run(["systemctl", "is-active", "auditd.service"])[1].strip() or None
        audit["rules_d_files"] = sorted(glob.glob("/etc/audit/rules.d/*.rules"))
    infra["auditd"] = audit

    infra["syslog_daemons"] = {n: bool(shutil.which(n)) for n in ("rsyslogd", "syslog-ng")}
    infra["log_file_meta"] = [m for m in map(file_meta, LOG_FILES) if m.get("exists")]
    try:
        du = shutil.disk_usage("/var/log")
        infra["var_log_free_percent"] = round(100 * du.free / du.total, 1)
    except OSError:
        infra["var_log_free_percent"] = None
    infra["logrotate_conf_present"] = os.path.exists("/etc/logrotate.conf")
    return infra


# ====================== main ======================

def collect(days: int = 7, max_lines: int = 5_000_000) -> dict:
    result = new_result("logs")
    if not result["ran_as_root"]:
        result["warnings"].append(
            "Not root: journal may only show YOUR messages unless you are in the "
            "systemd-journal/adm/wheel group. Re-run with sudo for full coverage.")

    data: dict = {"window_days": days}
    try:
        data["infrastructure"] = collect_infrastructure(result)
    except Exception as e:
        data["infrastructure"] = None
        result["errors"].append({"section": "infrastructure", "error": f"{type(e).__name__}: {e}"})

    if not shutil.which("journalctl"):
        result["warnings"].append("journalctl not found: auth event analysis skipped.")
        data["events"] = None
        result["data"] = data
        return result

    args = ["--since", f"{days} days ago"]
    for ident in AUTH_IDENTIFIERS:
        args += ["-t", ident]
    args += ["--output-fields=MESSAGE,SYSLOG_IDENTIFIER"]
    gen, get_err, state = stream_journal(args, max_lines)
    agg = Aggregator()
    bad = 0
    for line in gen:
        try:
            agg.feed(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    err = get_err().strip()
    if "not seeing messages from other users" in err:
        result["warnings"].append("journalctl reports you cannot see other users'/system messages: "
                                  "event counts are INCOMPLETE.")
    if "No journal files" in err or (agg.lines == 0 and err):
        result["warnings"].append(f"journalctl: {err[:150]}")
    if bad:
        result["errors"].append({"cmd": "journalctl", "error": f"{bad} unparsable JSON lines"})
    infra = data.get("infrastructure") or {}
    span = infra.get("journal_span") or {}
    if agg.lines == 0 and span.get("oldest_epoch") is None:
        result["warnings"].append(
            "Journal appears EMPTY or unreadable: zero events means 'no data', NOT 'no attacks'.")
    elif agg.lines == 0:
        result["warnings"].append(
            f"No auth events in the last {days} days, but the journal has data "
            "(check --days and that you are root).")
    ev = agg.result()
    ev["truncated_at_max_lines"] = state["truncated"]
    data["events"] = ev
    result["data"] = data
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect log infrastructure + auth event facts.")
    ap.add_argument("--days", type=int, default=7, help="journal window (default 7)")
    ap.add_argument("--max-lines", type=int, default=5_000_000)
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(a.days, a.max_lines), a.out, a.pretty)


if __name__ == "__main__":
    main()
