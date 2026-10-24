#!/usr/bin/env python3
"""vulnscan dashboard (Phase 5 preview, no ML).

Reads the JSON files written by the collectors (default: ./output/<collector>.json) and shows
one section per collector, with a rerun button. It displays FACTS; there is no scoring yet.

Run as your NORMAL user:   streamlit run dashboard/app.py
Do NOT run Streamlit as root (a web server with root rights is its own vulnerability).
For full-coverage data collect in a terminal:  sudo ./run_all.sh "$(which python)"
"""
import json
import os
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
ALLOWLIST = ROOT / "allowlist.yaml"
THRESHOLDS = ROOT / "thresholds.yaml"
DEFAULT_OUT = Path(os.environ.get("VULNSCAN_OUTPUT", ROOT / "output"))

COLLECTORS = {
    "accounts":    {"title": "Accounts",    "fast": []},
    "filesystem":  {"title": "Filesystem",  "fast": [], "note": "walks the whole disk: 1-3 min on a real system"},
    "processes":   {"title": "Processes",   "fast": ["--no-hidden-check"]},
    "services":    {"title": "Services",    "fast": ["--no-analyze"]},
    "packages":    {"title": "Packages",    "fast": ["--no-verify"], "note": "integrity check (pacman -Qkk) is slow"},
    "configs":     {"title": "Configs",     "fast": []},
    "network":     {"title": "Network",     "fast": []},
    "logs":        {"title": "Logs",        "fast": []},
    "kernel":      {"title": "Kernel",      "fast": []},
    "persistence": {"title": "Persistence", "fast": []},
}

EXPECTED_COLLECTOR_VERSION = "1.2"

st.set_page_config(page_title="vulnscan", page_icon="🛡️", layout="wide")


# ───────────────────────── helpers ─────────────────────────

def g(d, *keys, default=None):
    """Safe nested get: returns default if any level is missing/None."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
        if d is None:
            return default
    return d


def num(x, default=0.0):
    """Coerce numbers that may arrive as strings (e.g. exposure '9.6') to float."""
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def fmt_epoch(e):
    if not e:
        return "—"
    return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def fmt_age(iso):
    try:
        dt = datetime.fromisoformat(iso)
        s = (datetime.now(timezone.utc) - dt).total_seconds()
    except (TypeError, ValueError):
        return "?"
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            return f"{s / n:.0f}{unit} ago"
    return "just now"


def fmt_bytes(n):
    if n is None:
        return "—"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def tidy(rows) -> pd.DataFrame:
    """Make records Arrow-safe: lists/dicts -> text, mixed-type columns -> text."""
    df = pd.DataFrame(rows)
    for c in df.columns:
        df[c] = df[c].map(lambda v: ", ".join(map(str, v)) if isinstance(v, list)
                          else json.dumps(v, default=str) if isinstance(v, dict) else v)
        kinds = {type(v) for v in df[c] if v is not None and not (isinstance(v, float) and pd.isna(v))}
        if len(kinds) > 1:
            df[c] = df[c].map(lambda v: None if v is None else str(v))
    return df


def show(rows, empty="— none —", **kw):
    df = rows if isinstance(rows, pd.DataFrame) else tidy(rows or [])
    if df.empty:
        st.caption(empty)
        return
    try:
        st.dataframe(df, hide_index=True, width="stretch", **kw)
    except Exception:
        st.dataframe(df, hide_index=True, use_container_width=True, **kw)


def metrics(items: dict):
    cols = st.columns(len(items))
    for col, (k, v) in zip(cols, items.items()):
        col.metric(k, "—" if v is None else v)


def kv(d: dict | None, key="key", val="value"):
    show([{key: k, val: v} for k, v in (d or {}).items()])


def text_filter(label, key):
    return st.text_input(label, key=key, placeholder="type to filter…").strip().lower()


def match(row: dict, q: str) -> bool:
    return not q or q in json.dumps(row, default=str).lower()


# ───────────────────────── data + rerun ─────────────────────────

st.sidebar.title("🛡️ vulnscan")
out_dir = Path(st.sidebar.text_input("JSON folder", str(DEFAULT_OUT)))
python_bin = st.sidebar.text_input("Python for reruns", sys.executable)
fast_mode = st.sidebar.checkbox("Fast mode (skip slow checks)", True)
use_sudo = st.sidebar.checkbox("Rerun with `sudo -n`", False,
                               help="Only works if sudo needs no password. The web UI never asks for or "
                                    "sees your password, by design.")
st.sidebar.caption("Best practice: run this dashboard as your normal user and collect with "
                   "`sudo ./run_all.sh \"$(which python)\"` in a terminal.")
if st.sidebar.button("Reload JSON from disk"):
    st.cache_data.clear()
    st.rerun()


@st.cache_data(show_spinner=False)
def _load(path: str, mtime: float):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load(name):
    p = out_dir / f"{name}.json"
    if not p.exists():
        return None
    try:
        return _load(str(p), p.stat().st_mtime)
    except (OSError, json.JSONDecodeError) as e:
        return {"_load_error": str(e)}


def terminal_cmd(name):
    return f'sudo {python_bin} -m collectors.{name} --out {out_dir}/{name}.json --pretty'


def rerun(name):
    extra = COLLECTORS[name]["fast"] if fast_mode else []
    cmd = [python_bin, "-m", f"collectors.{name}", "--pretty", *extra]
    if use_sudo:
        cmd = ["sudo", "-n", *cmd]
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        return False, "timed out after 1 hour"
    except OSError as e:
        return False, str(e)
    try:
        json.loads(p.stdout)
    except json.JSONDecodeError:
        return False, (p.stderr.strip() or p.stdout.strip() or "no output")[-600:]
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / f".{name}.json.tmp"
    tmp.write_text(p.stdout, encoding="utf-8")       # written by the dashboard user -> no root-owned files
    tmp.replace(out_dir / f"{name}.json")
    return True, "ok"


def flash(level, msg):
    st.session_state.setdefault("flash", []).append((level, msg))


for level, msg in st.session_state.pop("flash", []):
    getattr(st, level)(msg)


def top(name):
    """Header for one collector tab. Returns its `data` dict or None."""
    info = COLLECTORS[name]
    c1, c2 = st.columns([5, 2])
    c1.subheader(info["title"])
    if c2.button(f"Rerun {name}", key=f"rr_{name}", width="stretch"):
        with st.spinner(f"Running collectors.{name} … {info.get('note', '')}"):
            ok, msg = rerun(name)
        if ok:
            st.cache_data.clear()
            flash("success", f"{name} re-collected.")
        else:
            flash("error", f"{name} failed: {msg}")
            if "password" in msg.lower() or "sudo" in msg.lower():
                flash("info", f"Run in a terminal instead:  {terminal_cmd(name)}")
        st.rerun()

    res = load(name)
    with st.expander("Terminal command"):
        st.code(terminal_cmd(name), language="bash")
    if res is None:
        st.info(f"No `{name}.json` in `{out_dir}` yet. Click Rerun, or run the command above.")
        return None
    if "_load_error" in res:
        st.error(f"Could not read {name}.json: {res['_load_error']}")
        return None

    m = st.columns(4)
    m[0].caption(f"**Collected:** {fmt_age(res.get('timestamp'))}")
    m[1].caption(f"**Host:** {res.get('host')}")
    m[2].caption("**Root:** " + ("yes" if res.get("ran_as_root") else "NO (reduced coverage)"))
    m[3].caption(f"**Schema:** {res.get('schema_version')} · collector v{res.get('collector_version', '?')}")
    if res.get("collector_version") != EXPECTED_COLLECTOR_VERSION:
        st.warning(f"This JSON came from an OLDER collector (v{res.get('collector_version', 'pre-1.1')}, "
                   f"expected v{EXPECTED_COLLECTOR_VERSION}). Update collectors/*.py and rerun, otherwise "
                   "you may be looking at already-fixed bugs (e.g. symlinks shown as 0777).")
    for w in res.get("warnings", []):
        st.warning(w)
    if res.get("errors"):
        with st.expander(f"{len(res['errors'])} collection error(s)"):
            show(res["errors"])
    return res.get("data") or {}


# ───────────────────────── renderers ─────────────────────────

def r_accounts(d):
    c = d.get("counts", {})
    metrics({"Accounts": c.get("total"), "Human": c.get("human"), "System": c.get("system"),
             "Login shell": c.get("with_login_shell"), "UID 0": len(g(d, "integrity", "uid0_accounts", default=[]))})
    t1, t2, t3, t4 = st.tabs(["Users", "Privileged groups", "Integrity facts", "Policy & files"])
    with t1:
        types = st.multiselect("Account type", ["root_uid", "human", "system", "nobody"],
                               default=["root_uid", "human", "system", "nobody"], key="acc_t")
        only_login = st.checkbox("Only accounts with a login shell", key="acc_l")
        rows = []
        for u in d.get("users", []):
            if u["account_type"] not in types or (only_login and not u["has_login_shell"]):
                continue
            pw = u.get("password") or {}
            rows.append({"name": u["name"], "uid": u["uid"], "type": u["account_type"], "shell": u["shell"],
                         "login_shell": u["has_login_shell"], "home": u["home"],
                         "home_mode": g(u, "home_meta", "mode"), "privileged_groups": u["privileged_groups"],
                         "pw_state": pw.get("state"), "pw_algo": pw.get("algorithm"),
                         "pw_age_days": pw.get("days_since_change"), "logged_in": u["currently_logged_in"]})
        show(rows)
        st.caption("Live sessions"); show(d.get("sessions"))
    with t2:
        pm = d.get("privileged_group_members", {})
        show([{"group": k, "members": v} for k, v in pm.items()])
    with t3:
        st.json(d.get("integrity", {}))
    with t4:
        st.caption("login.defs (subset)"); kv(d.get("login_defs"))
        st.caption("Account file permissions"); show(d.get("account_file_meta"))


def r_filesystem(d):
    s, t = d.get("scan", {}), d.get("totals", {})
    metrics({"Files scanned": s.get("files_scanned"), "Dirs scanned": s.get("dirs_scanned"),
             "Denied dirs": s.get("denied_dirs"), "Seconds": s.get("elapsed_seconds")})
    metrics({"SUID": t.get("suid_files"), "SGID": t.get("sgid_files"),
             "World-writable files": t.get("world_writable_files"),
             "WW dirs (no sticky)": t.get("world_writable_dirs_no_sticky"), "Unowned": t.get("unowned_files")})
    if any((s.get("truncated") or {}).values()):
        st.warning(f"Some lists were capped at {s.get('list_cap')} entries: {s.get('truncated')}")
    tabs = st.tabs(["SUID", "SGID", "World-writable files", "World-writable dirs", "Unowned",
                    "Capabilities", "Mounts", "Sensitive paths"])
    only_unpkg = None
    with tabs[0]:
        only_unpkg = st.checkbox("Only files NOT owned by a package", key="fs_un")
        rows = [r for r in d.get("suid_files", []) if not only_unpkg or r.get("owned_by_package") is False]
        show(rows)
    with tabs[1]:
        show(d.get("sgid_files"))
    with tabs[2]:
        show(d.get("world_writable_files"))
    with tabs[3]:
        st.caption(f"Sticky-bit world-writable dirs (normal): {t.get('world_writable_dirs_sticky')}")
        show(d.get("world_writable_dirs_no_sticky"))
    with tabs[4]:
        show(d.get("unowned_files"))
    with tabs[5]:
        caps = d.get("capabilities")
        show(caps) if caps is not None else st.caption("getcap not available")
    with tabs[6]:
        st.caption("Key paths: which mount covers them and its options"); show(d.get("key_mounts"))
        st.caption("Pruned mountpoints: " + ", ".join(s.get("pruned_mountpoints", [])))
    with tabs[7]:
        show(d.get("sensitive_paths"))


def r_processes(d):
    c = d.get("counts", {})
    metrics({"Userspace": c.get("userspace"), "Kernel threads": c.get("kernel_threads"),
             "Deleted exe": c.get("exe_deleted"), "memfd exe": c.get("exe_memfd"),
             "exe in /tmp": c.get("exe_under_tmp"), "uid real≠eff": c.get("uid_real_ne_effective")})
    h = d.get("hidden_pid_check", {})
    if h.get("performed"):
        hid = h.get("suspected_hidden_pids", [])
        (st.error if hid else st.success)(f"Hidden-PID sweep ({h.get('elapsed_seconds')}s): "
                                          f"{len(hid)} suspected hidden PID(s) {hid or ''}")
    else:
        st.caption("Hidden-PID sweep not performed (fast mode).")
    q = text_filter("Search name / exe / cmdline / user", "pr_q")
    f = st.multiselect("Show only", ["exe deleted", "exe in memory (memfd)", "exe in /tmp-like dir",
                                     "real≠effective uid", "not owned by a package"], key="pr_f")
    rows = []
    for p in d.get("processes", []):
        if p.get("kernel_thread"):
            continue
        if ("exe deleted" in f and not p.get("exe_deleted")) or ("exe in memory (memfd)" in f and not p.get("exe_memfd")) \
           or ("exe in /tmp-like dir" in f and not p.get("exe_under_tmp")) \
           or ("real≠effective uid" in f and not p.get("uid_real_ne_effective")) \
           or ("not owned by a package" in f and p.get("owned_by_package") is not False):
            continue
        row = {"pid": p["pid"], "ppid": p["ppid"], "name": p["name"], "user": p.get("user"), "exe": p.get("exe"),
               "deleted": p.get("exe_deleted"), "memfd": p.get("exe_memfd"), "pkg": p.get("package"),
               "unit": p.get("systemd_unit"), "caps": p.get("cap_effective"), "seccomp": p.get("seccomp_mode"),
               "nnp": p.get("no_new_privs"), "cmdline": p.get("cmdline")}
        if match(row, q):
            rows.append(row)
    st.caption(f"{len(rows)} processes shown"); show(rows)
    st.caption("Processes by user"); st.bar_chart(pd.Series(c.get("by_user", {})))


def r_services(d):
    if not d.get("systemd_available", True):
        st.error("systemd not available"); return
    c = d.get("counts", {})
    metrics({"systemd": d.get("systemd_version"), "Loaded": c.get("services_loaded"),
             "Running": c.get("services_running"), "Enabled": c.get("services_enabled"),
             "Running as root": c.get("services_running_as_root"), "Failed": len(d.get("failed_units", []))})
    if not d.get("manager_running"):
        st.warning("systemd was not the running init when collected: only unit-file states are available.")
    t1, t2, t3 = st.tabs(["Services", "Sockets", "Unit files"])
    with t1:
        q = text_filter("Search", "sv_q")
        run_only = st.checkbox("Only running", key="sv_r")
        rows = []
        for s in d.get("services", []):
            if run_only and s["sub"] != "running":
                continue
            h = s.get("hardening", {})
            row = {"name": s["name"], "sub": s["sub"], "enabled": s["unit_file_state"], "user": s["effective_user"],
                   "exposure": s.get("security_exposure"), "predicate": s.get("security_predicate"),
                   "no_new_privs": h.get("no_new_privileges"), "protect_system": h.get("protect_system"),
                   "private_tmp": h.get("private_tmp"), "unit_pkg_owned": s.get("fragment_owned_by_package"),
                   "dropins": len(s.get("dropins", [])),
                   "exec": [e.get("path") for e in s.get("exec_start", [])]}
            if match(row, q):
                rows.append(row)
        rows.sort(key=lambda r: -num(r["exposure"]))
        show(rows)
        st.caption("Failed units: " + (", ".join(d.get("failed_units", [])) or "none"))
    with t2:
        show(d.get("sockets"))
    with t3:
        st.bar_chart(pd.Series(d.get("unit_file_state_counts", {})))
        show(d.get("unit_files"))


def r_packages(d):
    if not d.get("pacman_available", True):
        st.error("pacman database not found: not an Arch system (or not readable)."); return
    c, u = d.get("counts", {}), d.get("updates", {})
    metrics({"Installed": c.get("installed"), "Explicit": c.get("explicit"), "Foreign/AUR": c.get("foreign"),
             "Orphans": c.get("orphans"), "Updates pending": c.get("updates_pending"),
             "Sync DB age (d)": u.get("sync_db_age_days")})
    st.caption(f"Last full upgrade: {g(u, 'last_full_upgrade', 'timestamp', default='unknown')} "
               f"({g(u, 'last_full_upgrade', 'days_ago', default='?')} days ago) · update method: {u.get('method')}")
    t1, t2, t3, t4 = st.tabs(["Installed", "Updates & orphans", "Repos & mirrors", "Integrity"])
    with t1:
        q = text_filter("Search name / packager / url", "pk_q")
        f = st.multiselect("Show only", ["foreign", "explicit", "dependency", "unsigned"], key="pk_f")
        rows = []
        for p in d.get("packages", []):
            if ("foreign" in f and not p.get("foreign")) or ("explicit" in f and p["install_reason"] != "explicit") \
               or ("dependency" in f and p["install_reason"] != "dependency") \
               or ("unsigned" in f and "pgp" in p.get("validation", [])):
                continue
            row = {"name": p["name"], "version": p["version"], "upstream": p["upstream_version"], "reason": p["install_reason"],
                   "foreign": p.get("foreign"), "validation": p.get("validation"), "packager": p.get("packager"),
                   "installed": fmt_epoch(p.get("install_date")), "size": fmt_bytes(p.get("size_bytes"))}
            if match(row, q):
                rows.append(row)
        st.caption(f"{len(rows)} packages"); show(rows)
    with t2:
        st.caption("Pending updates"); show(u.get("pending"))
        st.caption("Orphaned dependencies"); show([{"package": o} for o in d.get("orphans") or []])
    with t3:
        st.caption("Options"); kv(g(d, "pacman_conf", "options"))
        show([{"repo": r["name"], "sig_level": r["sig_level"], "servers": r["servers"], "includes": r["includes"]}
              for r in g(d, "pacman_conf", "repos", default=[])])
        st.json(d.get("mirrors", {}))
    with t4:
        i = d.get("integrity", {})
        if not i.get("performed"):
            st.info("Integrity check not performed (needs root, and is skipped in fast mode).")
        else:
            st.caption(f"Took {i.get('elapsed_seconds')}s · totals {i.get('totals')} · {i.get('note')}")
            only = st.checkbox("Only content-changed (size/checksum) files", True, key="pk_cc")
            show([r for r in i.get("altered_files", []) if not only or r.get("content_changed")])
            st.caption("Missing files"); show(i.get("missing_files"))
            st.caption("Modified config (backup) files — usually expected"); show(i.get("backup_files_modified"))


def r_configs(d):
    t = st.tabs(["SSH", "sudoers", "login.defs", "fstab", "PAM"])
    with t[0]:
        ssh = d.get("ssh") or {}
        if not ssh.get("installed", True):
            st.info("sshd not installed")
        else:
            eff = ssh.get("effective")
            if eff is None:
                st.warning(f"Effective sshd config unavailable: {ssh.get('effective_error')}")
            else:
                q = text_filter("Filter settings", "ssh_q")
                show([{"setting": k, "value": v} for k, v in eff.items() if match({"k": k, "v": v}, q)])
            st.caption(f"Match blocks in config: {ssh.get('match_blocks')}")
            st.caption("Config files"); show(ssh.get("config_files"))
            st.caption("Host private keys"); show(ssh.get("host_private_keys"))
    with t[1]:
        s = d.get("sudoers") or {}
        if not s.get("installed", True):
            st.info("sudo not installed")
        elif not s.get("readable"):
            st.warning("sudoers unreadable (needs root).")
        else:
            st.json(s.get("summary", {}))
            st.caption("Global Defaults"); kv(s.get("global_defaults"), "default", "value")
            show([{"file": e["file"], "line": e["line"], "type": e["type"], "who": e.get("who"), "runas": e.get("runas"),
                   "nopasswd": e.get("nopasswd"), "all_cmds": e.get("runs_all_commands"),
                   "wildcard": e.get("has_wildcard_command"), "raw": e["raw"]} for e in s.get("entries", [])])
            st.caption(f"Syntax check: {s.get('syntax_check')}  ·  Ignored by sudo: {s.get('ignored_files')}")
            st.info(s.get("note", ""))
    with t[2]:
        kv(g(d, "login_defs", "values"), "key", "value")
    with t[3]:
        show(g(d, "fstab", "entries"))
    with t[4]:
        p = d.get("pam") or {}
        st.json(p.get("summary", {}))
        c1, c2 = st.columns(2)
        c1.caption("faillock.conf"); c1.json(p.get("faillock_conf") or {})
        c2.caption("pwquality.conf"); c2.json(p.get("pwquality_conf") or {})
        files = p.get("files", {})
        sel = st.selectbox("PAM file", sorted(files), key="pam_sel") if files else None
        if sel:
            show(files[sel]["entries"])


def r_network(d):
    c = d.get("counts", {})
    metrics({"Listening": c.get("listening_total"), "TCP": c.get("tcp_listening"),
             "TCP on all ifaces": c.get("tcp_all_interfaces"), "TCP loopback": c.get("tcp_loopback_only"),
             "UDP bound": c.get("udp_bound"), "PID unknown": c.get("listening_pid_unknown")})
    t = st.tabs(["Listening", "Connections", "Interfaces", "Firewall", "DNS & sockets"])
    with t[0]:
        scopes = st.multiselect("Scope", ["all_interfaces", "loopback", "private", "link_local", "public"],
                                default=["all_interfaces", "loopback", "private", "link_local", "public"], key="nw_s")
        show([s for s in d.get("listening", []) if s.get("scope") in scopes])
    with t[1]:
        cn = d.get("connections", {})
        st.caption(f"By status: {cn.get('by_status')}  ·  remote TCP: {cn.get('total_remote_tcp')}")
        show(cn.get("list"))
    with t[2]:
        show([{**{k: v for k, v in i.items() if k != "addresses"},
               "addresses": [f"{a['family']}:{a['address']}" for a in i["addresses"]]} for i in d.get("interfaces", [])])
    with t[3]:
        fw = d.get("firewall", {})
        st.write("Frameworks present:", ", ".join(fw.get("frameworks_present", [])) or "none")
        nft = fw.get("nftables")
        if nft:
            if nft.get("readable"):
                st.caption(f"nftables: {len(nft.get('tables', []))} tables, {nft.get('total_rules')} rules")
                show(nft.get("base_chains"))
                with st.expander("Ruleset text"):
                    st.code(nft.get("ruleset_text") or "", language="text")
            else:
                st.warning(f"nftables unreadable: {nft.get('error')}")
        for tool, v in (fw.get("iptables") or {}).items():
            st.caption(f"{tool}: " + (f"policies {v.get('policies')} · {v.get('rule_count')} rules · {v.get('version')}"
                                      if v.get("readable") else f"unreadable ({v.get('error')})"))
        if fw.get("ufw"):
            st.caption(f"ufw: {fw['ufw'].get('status')} {fw['ufw'].get('defaults')}")
        if fw.get("firewalld"):
            st.caption(f"firewalld: {fw['firewalld']}")
        st.caption("Services that restore rules at boot")
        show([{"unit": k, **v} for k, v in (fw.get("services") or {}).items()])
    with t[4]:
        st.caption("Resolvers"); show(g(d, "dns", "nameservers"))
        st.caption("Privileged local sockets"); show(d.get("special_sockets"))


def r_logs(d):
    infra, ev = d.get("infrastructure") or {}, d.get("events")
    span = infra.get("journal_span") or {}
    metrics({"Journal size": fmt_bytes(infra.get("journal_disk_usage_bytes")),
             "Oldest entry": fmt_epoch(span.get("oldest_epoch")),
             "Persistent": infra.get("persistent_journal_dir_exists"),
             "auditd": "installed" if g(infra, "auditd", "installed") else "not installed",
             "/var/log free %": infra.get("var_log_free_percent")})
    t = st.tabs(["SSH", "sudo & su", "Accounts & crashes", "Infrastructure"])
    if not ev:
        for x in t[:3]:
            x.info("No event data collected.")
    else:
        ssh, sd = ev.get("ssh", {}), ev.get("sudo", {})
        with t[0]:
            metrics({"Failed": ssh.get("failed_total"), "Invalid user": ssh.get("invalid_user_total"),
                     "Accepted": ssh.get("accepted_total"), "Root logins": ssh.get("accepted_root_logins"),
                     "Distinct sources": ssh.get("distinct_failed_sources"), "Scanner noise": ssh.get("scanner_noise_events")})
            st.caption(f"Window: {fmt_epoch(ev.get('first_event_epoch'))} → {fmt_epoch(ev.get('last_event_epoch'))} · "
                       f"{ev.get('journal_lines_processed')} lines")
            c1, c2 = st.columns(2)
            with c1:
                st.caption("Top failed sources"); show(ssh.get("top_failed_sources"))
            with c2:
                st.caption("Top attempted usernames"); show(ssh.get("top_attempted_usernames"))
            st.caption("Accepted logins"); show([{**a, "last_seen": fmt_epoch(a.get("last_seen_epoch"))} for a in ssh.get("accepted", [])])
        with t[1]:
            metrics({"sudo commands": sd.get("commands_total")})
            c1, c2 = st.columns(2)
            with c1:
                st.caption("Top commands (programs only)"); show(sd.get("top_commands"))
                st.caption("By user"); kv(sd.get("by_user"), "user", "count")
            with c2:
                st.caption("Not in sudoers"); kv(sd.get("not_in_sudoers"), "user", "count")
                st.caption("Wrong password"); kv(sd.get("incorrect_password"), "user", "count")
                st.caption("PAM auth failures"); kv(sd.get("pam_auth_failures"), "user", "count")
            st.caption("su"); st.json(ev.get("su", {}))
            st.caption(f"Console login failures: {ev.get('console_login_failures')}")
        with t[2]:
            ac = ev.get("account_changes", {})
            st.caption(f"Account-change events: {ac.get('total')}")
            show([{**e, "time": fmt_epoch(e.get("epoch"))} for e in ac.get("events", [])])
            cd = ev.get("coredumps", {})
            st.caption(f"Coredumps: {cd.get('total')}"); show(cd.get("by_process"))
    with t[3]:
        st.caption("journald config"); kv(infra.get("journald_config"))
        st.caption("auditd"); st.json(infra.get("auditd", {}))
        st.caption("Log file permissions"); show(infra.get("log_file_meta"))


def r_kernel(d):
    mac, tn = d.get("mac_lockdown", {}), d.get("taint", {})
    metrics({"Release": d.get("release"), "Taint": tn.get("value"), "Secure Boot": mac.get("secure_boot"),
             "Lockdown": mac.get("lockdown"), "Modules loaded": g(d, "modules", "loaded_count")})
    rc = d.get("reboot_check", {})
    if rc.get("running_kernel_modules_on_disk") is False:
        st.error("The running kernel's module tree is no longer on disk: you are running an old kernel. Reboot.")
    t = st.tabs(["sysctl", "Boot cmdline", "Modules", "CPU mitigations", "LSM / lockdown", "Taint"])
    with t[0]:
        q = text_filter("Filter", "kn_q")
        show([{"key": k, "value": v} for k, v in d.get("sysctl", {}).items() if match({"k": k}, q)])
        st.caption("Config files: " + ", ".join(d.get("sysctl_config_files", [])))
    with t[1]:
        st.code(g(d, "cmdline", "raw", default=""), language="text")
        kv(g(d, "cmdline", "params"), "param", "value")
    with t[2]:
        m = d.get("modules", {})
        st.caption(f"Blacklisted: {m.get('blacklisted')}  ·  install overrides: {m.get('install_overrides')}  ·  autoload: {m.get('autoload')}")
        show(m.get("loaded"))
    with t[3]:
        show([{"vulnerability": k, "status": v} for k, v in (d.get("cpu_mitigations") or {}).items()])
    with t[4]:
        st.json(mac); st.json(rc)
    with t[5]:
        st.write(tn.get("flags") or "Not tainted")


def r_persistence(d):
    c = d.get("counts", {})
    metrics({"Users scanned": len(d.get("users_scanned", [])), "Records": c.get("records"),
             "Not package-owned": c.get("unowned_files"), "With pattern hits": c.get("with_pattern_hits"),
             "World-writable": c.get("world_writable")})
    st.caption("Pattern hits are regex matches on text (e.g. `pipe_to_shell`), not verdicts: legitimate installers match too.")
    t = st.tabs(["Cron", "systemd", "Shell & autostart", "SSH keys", "Other"])
    with t[0]:
        rows = [{"file": f["path"], "pkg_owned": f.get("owned_by_package"), **e}
                for f in (d.get("cron") or {}).get("system", []) + (d.get("cron") or {}).get("user", [])
                for e in f.get("entries", [])]
        show(rows)
        st.caption("cron.{hourly,daily,weekly,monthly} scripts"); show(g(d, "cron", "scripts"))
    with t[1]:
        sd = d.get("systemd") or {}
        st.caption("Locally created units & drop-ins"); show(sd.get("local_units"))
        st.caption("Symlinks pointing outside systemd dirs"); show(sd.get("symlinks_outside_systemd_dirs"))
        st.caption("Enabled timers: " + (", ".join(sd.get("enabled_timers", [])) or "none"))
    with t[2]:
        users = (d.get("shell") or {}).get("users", {})
        who = st.selectbox("User", sorted(users), key="ps_u") if users else None
        if who:
            show(users[who])
        st.caption("System-wide"); show(g(d, "shell", "system"))
    with t[3]:
        rows = [{"user": a["user"], "file": a["path"], "mode": a.get("mode"), **k}
                for a in d.get("ssh_authorized_keys", []) for k in a.get("keys", [])]
        show(rows)
    with t[4]:
        m = d.get("misc") or {}
        st.caption("/etc/ld.so.preload"); st.json(m.get("ld_so_preload", {}))
        st.caption("pacman hooks (local)"); show(m.get("pacman_hooks"))
        st.caption("udev rules (local)"); show(m.get("udev_rules_local"))
        st.caption("modules-load.d"); show(m.get("modules_load_d"))
        st.caption("ld.so.conf"); show(m.get("ld_so_conf_files"))


RENDER = {"accounts": r_accounts, "filesystem": r_filesystem, "processes": r_processes, "services": r_services,
          "packages": r_packages, "configs": r_configs, "network": r_network, "logs": r_logs,
          "kernel": r_kernel, "persistence": r_persistence}


# ───────────────────────── findings (rule engine) ─────────────────────────

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def run_engine():
    cmd = [python_bin, "-m", "engine", "--output", str(out_dir),
           "--thresholds", str(THRESHOLDS), "--allowlist", str(ALLOWLIST)]
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)
    return p.returncode == 0, (p.stderr.strip() or p.stdout.strip())[-600:]


def findings_tab():
    c1, c2 = st.columns([5, 2])
    c1.subheader("Findings")
    if c2.button("Run rule engine", key="run_engine", width="stretch"):
        with st.spinner("Evaluating rules ..."):
            ok, msg = run_engine()
        flash("success" if ok else "error", "Rule engine finished." if ok else f"Rule engine failed: {msg}")
        st.cache_data.clear()
        st.rerun()
    with st.expander("Terminal command"):
        st.code(f"{python_bin} -m engine --output {out_dir}", language="bash")

    rep = load("findings")
    if rep is None:
        st.info("No findings.json yet. Collect data first, then click 'Run rule engine'.")
        return
    if "_load_error" in rep:
        st.error(f"Could not read findings.json: {rep['_load_error']}")
        return

    cov = rep.get("coverage", {})
    unknown = cov.get("unknown", 0) + cov.get("error", 0)
    banner = (f"Coverage: {cov.get('evaluated')} of {cov.get('rules_total')} rules evaluated · "
              f"{cov.get('pass')} pass · {cov.get('fail')} with findings · {unknown} UNKNOWN · {cov.get('na')} N/A")
    (st.warning if unknown else st.success)(banner + (" · UNKNOWN means 'could not check', not 'safe'." if unknown else ""))
    bad = {n: v for n, v in cov.get("collectors", {}).items() if v.get("status") != "ok"}
    if bad:
        st.error("Collector data problems: " + "; ".join(f"{n}: {v.get('reason')}" for n, v in bad.items()))
    if cov.get("unknown_reasons"):
        with st.expander(f"Why {unknown} rule(s) are UNKNOWN"):
            show(cov["unknown_reasons"])
    al = rep.get("allowlist", {})
    if al.get("expired") or al.get("invalid"):
        st.warning(f"Allowlist: {len(al.get('expired', []))} expired entr(ies), {len(al.get('invalid', []))} invalid entr(ies) ignored.")

    allf = rep.get("findings", [])
    live = [f for f in allf if not f["suppressed"]]
    metrics({s.capitalize(): sum(f["severity"] == s for f in live) for s in SEV_ORDER})

    c1, c2, c3 = st.columns(3)
    sevs = c1.multiselect("Severity", SEV_ORDER, default=SEV_ORDER, key="fd_sev")
    cats = c2.multiselect("Category", sorted({f["category"] for f in allf}), default=sorted({f["category"] for f in allf}), key="fd_cat")
    q = c3.text_input("Search", key="fd_q", placeholder="rule, subject, text ...").strip().lower()
    show_sup = st.checkbox("Show suppressed findings", key="fd_sup")
    rows = [f for f in allf if f["severity"] in sevs and f["category"] in cats and (show_sup or not f["suppressed"])
            and (not q or q in json.dumps(f, default=str).lower())]
    show([{"severity": f["severity"], "conf": f["confidence"], "rule": f["rule_id"], "title": f["title"],
           "subject": f["subject"], "category": f["category"],
           "net-exposed": f["features"].get("network_exposed"), "root": f["features"].get("runs_as_root"),
           "suppressed": f["suppressed"]} for f in rows], empty="No findings match the filters.")

    if rows:
        labels = [f"[{f['severity'].upper()}] {f['rule_id']}  {f['subject'][:80]}" for f in rows]
        i = labels.index(st.selectbox("Details", labels, key="fd_sel"))
        f = rows[i]
        st.markdown(f"**{f['title']}**  \nSeverity `{f['severity']}` · confidence `{f['confidence']}` · category `{f['category']}` · rule v{f['rule_version']}")
        st.markdown(f"**Why it matters.** {f['why']}")
        st.markdown(f"**What to do.** {f['fix']}")
        st.caption(f"Evidence ({f['evidence_total']} total, up to 10 shown)")
        show(f["evidence"])
        if f["suppressed"]:
            st.info(f"Suppressed: {f['suppression']['reason']} (expires {f['suppression']['expires']})")
        else:
            with st.expander("Suppress this finding (adds an allowlist entry)"):
                with st.form("suppress_form"):
                    reason = st.text_input("Reason (required)")
                    exp = st.date_input("Expires", value=date.today() + timedelta(days=90))
                    pin = st.checkbox("Pin to the file's sha256", value=bool(f["attrs"].get("sha256")),
                                      disabled=not f["attrs"].get("sha256"))
                    go = st.form_submit_button("Add to allowlist")
                if go:
                    if not reason.strip():
                        st.error("A reason is required.")
                    else:
                        from engine.allowlist import append_entry
                        entry = {"rule_id": f["rule_id"], "subject": f["subject"], "reason": reason.strip(), "expires": exp}
                        if pin and f["attrs"].get("sha256"):
                            entry["sha256"] = f["attrs"]["sha256"]
                        append_entry(str(ALLOWLIST), entry)
                        ok, msg = run_engine()
                        st.cache_data.clear()
                        flash("success" if ok else "error", f"Added to allowlist and re-ran the engine." if ok else f"Allowlist updated but engine failed: {msg}")
                        st.rerun()

    with st.expander("All rules and their outcomes"):
        show([{"rule": r["rule_id"], "outcome": r["outcome"], "findings": r["finding_count"],
               "suppressed": r["suppressed_count"], "reason": r["reason"], "title": r["title"]} for r in rep.get("rules", [])])
    st.caption(f"Engine v{rep.get('engine_version')} · scan {rep.get('scan_timestamp')}")



# ───────────────────────── overview + layout ─────────────────────────

def overview():
    st.subheader("Overview")
    rows, warns = [], []
    for name, info in COLLECTORS.items():
        p = out_dir / f"{name}.json"
        res = load(name) if p.exists() else None
        ok = isinstance(res, dict) and "_load_error" not in res
        rows.append({"collector": info["title"], "file": "yes" if ok else "—",
                     "collected": fmt_age(res.get("timestamp")) if ok else "—",
                     "root": res.get("ran_as_root") if ok else None,
                     "warnings": len(res.get("warnings", [])) if ok else None,
                     "errors": len(res.get("errors", [])) if ok else None,
                     "size": fmt_bytes(p.stat().st_size) if p.exists() else "—"})
        if ok:
            warns += [(info["title"], w) for w in res.get("warnings", [])]
    show(rows)
    if st.button("Rerun ALL collectors"):
        bar = st.progress(0.0)
        for i, name in enumerate(COLLECTORS, 1):
            with st.spinner(f"{name} …"):
                ok, msg = rerun(name)
            flash("success" if ok else "error", f"{name}: {'ok' if ok else msg}")
            bar.progress(i / len(COLLECTORS))
        ok, msg = run_engine()
        flash("success" if ok else "error", "rule engine: ok" if ok else f"rule engine: {msg}")
        st.cache_data.clear()
        st.rerun()
    st.markdown("**Full-coverage collection (recommended):**")
    st.code('sudo ./run_all.sh "$(which python)"          # add --fast to skip slow checks', language="bash")
    if warns:
        st.markdown("**Collector warnings**")
        show([{"collector": a, "warning": b} for a, b in warns])
    st.caption("This dashboard shows collected facts only. Scoring and prioritisation come in later phases.")


tabs = st.tabs(["Overview", "Findings"] + [v["title"] for v in COLLECTORS.values()])
with tabs[0]:
    overview()
with tabs[1]:
    try:
        findings_tab()
    except Exception as e:
        st.error(f"Could not render findings: {type(e).__name__}: {e}")
for tab, name in zip(tabs[2:], COLLECTORS):
    with tab:
        data = top(name)
        if data is not None:
            try:
                RENDER[name](data)
            except Exception as e:            # one broken renderer must not blank the whole app
                st.error(f"Could not render {name}: {type(e).__name__}: {e}")
                with st.expander("Raw data"):
                    st.json(data)
