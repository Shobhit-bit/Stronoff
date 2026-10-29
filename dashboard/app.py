#!/usr/bin/env python3
"""vulnscan dashboard (with Offline ML Vulnerability & Finding Prioritization).

Reads the JSON files written by the collectors (default: ./output/<collector>.json),
extracts security findings, ranks them using the pre-trained ML model (ml/vuln_ranker_model.pkl),
and shows one section per collector with a rerun button.

Run as your NORMAL user:   streamlit run dashboard/app.py
Do NOT run Streamlit as root (a web server with root rights is its own vulnerability).
For full-coverage data collect in a terminal:  sudo ./run_all.sh "$(which python)"
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = Path(os.environ.get("VULNSCAN_OUTPUT", ROOT / "output"))
MODEL_PATH = r"/home/arc/Code/vulnscan_v1/ml/vuln_ranker_model.pkl"

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

EXPECTED_COLLECTOR_VERSION = "1.1"

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


# ───────────────────────── ML inference & extraction ─────────────────────────

@st.cache_resource
def load_ml_artifact(path: str):
    p = Path(path)
    if not p.exists():
        return None
    return joblib.load(p)


def extract_host_candidates() -> list[dict]:
    """
    Extracts concrete security findings from the 10 collector JSON schemas
    and maps them into feature vectors: [cvss_base, epss_score, epss_percentile, exposure_weight].
    """
    candidates = []

    def add(module, finding, cvss, epss, pct, exp, cve="Host Finding"):
        candidates.append({
            "Module": module,
            "Finding": finding,
            "CVE / Type": cve,
            "cvss_base": float(cvss),
            "epss_score": float(epss),
            "epss_percentile": float(pct),
            "exposure_weight": float(exp),
        })

    # 1. Accounts
    acc = g(load("accounts"), "data") or {}
    for u in g(acc, "integrity", "uid0_accounts", default=[]):
        if u != "root":
            add("accounts", f"Non-root account with UID 0: {u}", 9.5, 0.75, 0.95, 0.90)
    for u in acc.get("users", []):
        if g(u, "password", "state") == "empty":
            add("accounts", f"User '{u.get('name')}' has an EMPTY password", 9.8, 0.85, 0.98, 0.95)

    # 2. Filesystem
    fs = g(load("filesystem"), "data") or {}
    for f in fs.get("suid_files", []):
        if f.get("owned_by_package") is False:
            add("filesystem", f"Unpackaged SUID binary: {f.get('path')}", 8.8, 0.60, 0.90, 0.85)
    for f in fs.get("world_writable_files", [])[:30]:
        add("filesystem", f"World-writable file: {f.get('path')}", 6.5, 0.25, 0.65, 0.60)
    for d_item in fs.get("world_writable_dirs_no_sticky", [])[:20]:
        add("filesystem", f"WW dir without sticky bit: {d_item.get('path')}", 5.5, 0.15, 0.50, 0.55)

    # 3. Processes
    pr = g(load("processes"), "data") or {}
    for pid in g(pr, "hidden_pid_check", "suspected_hidden_pids", default=[]):
        add("processes", f"Suspected hidden PID detected: {pid}", 9.8, 0.85, 0.97, 0.95)
    for p in pr.get("processes", []):
        if p.get("exe_memfd"):
            add("processes", f"Fileless memfd process: {p.get('name')} (PID {p.get('pid')})", 9.0, 0.70, 0.92, 0.90)
        elif p.get("exe_under_tmp"):
            add("processes", f"Process running from /tmp: {p.get('exe')} (PID {p.get('pid')})", 8.2, 0.55, 0.85, 0.85)
        elif p.get("exe_deleted"):
            add("processes", f"Process running deleted binary: {p.get('name')} (PID {p.get('pid')})", 6.0, 0.20, 0.55, 0.65)

    # 4. Services (uses systemd security_exposure 0-10 directly!)
    sv = g(load("services"), "data") or {}
    for s in sv.get("services", []):
        if s.get("sub") == "running":
            exp_val = num(s.get("security_exposure"), 0.0)
            if exp_val >= 7.5:
                add("services", f"High-exposure running service: {s.get('name')} (exposure {exp_val})",
                    exp_val, exp_val / 15.0, exp_val / 10.0, 0.85)

    # 5. Packages (pending updates & altered binaries)
    pk = g(load("packages"), "data") or {}
    for u in g(pk, "updates", "pending", default=[])[:50]:
        pkg_name = u.get("name") if isinstance(u, dict) else str(u)
        add("packages", f"Outdated package pending update: {pkg_name}", 7.5, 0.35, 0.75, 0.80, "Pending Update")
    for alt in g(pk, "integrity", "altered_files", default=[])[:30]:
        if alt.get("content_changed"):
            add("packages", f"Package file checksum modified: {alt.get('path')} ({alt.get('package')})",
                8.0, 0.45, 0.82, 0.75)

    # 6. Configs (SSH & sudoers)
    cf = g(load("configs"), "data") or {}
    ssh_eff = g(cf, "ssh", "effective") or {}
    if str(ssh_eff.get("permitrootlogin", "")).lower() in ("yes", "without-password", "prohibit-password"):
        if str(ssh_eff.get("permitrootlogin", "")).lower() == "yes":
            add("configs", "SSHD PermitRootLogin is enabled ('yes')", 8.5, 0.55, 0.88, 0.90)
    if str(ssh_eff.get("permitemptypasswords", "")).lower() == "yes":
        add("configs", "SSHD PermitEmptyPasswords is enabled", 9.8, 0.85, 0.98, 0.95)
    for e in g(cf, "sudoers", "entries", default=[]):
        if e.get("nopasswd") and e.get("runs_all_commands"):
            add("configs", f"Sudoers NOPASSWD ALL granted to {e.get('who')}", 8.5, 0.50, 0.85, 0.80)

    # 7. Network (Wildcard 0.0.0.0 / :: listening sockets)
    nw = g(load("network"), "data") or {}
    for sock in nw.get("listening", []):
        if sock.get("scope") == "all_interfaces":
            add("network", f"Port {sock.get('local_port')}/{sock.get('proto')} exposed on all interfaces ({sock.get('process') or 'unknown'})",
                7.2, 0.35, 0.72, 0.95)

    # 8. Kernel
    kn = g(load("kernel"), "data") or {}
    if g(kn, "reboot_check", "running_kernel_modules_on_disk") is False:
        add("kernel", f"Running outdated kernel ({kn.get('release')}): module tree missing, reboot required",
            8.2, 0.50, 0.85, 0.85)
    for vuln_name, status in (kn.get("cpu_mitigations") or {}).items():
        if "vulnerable" in str(status).lower():
            add("kernel", f"CPU vulnerability unmitigated ({vuln_name}): {status}", 7.8, 0.40, 0.80, 0.80, "CPU Hardware Vuln")

    # 9. Persistence
    ps = g(load("persistence"), "data") or {}
    if g(ps, "misc", "ld_so_preload", "exists"):
        add("persistence", "/etc/ld.so.preload exists (potential userland rootkit hook)", 9.5, 0.80, 0.95, 0.90)
    for unit in g(ps, "systemd", "local_units", default=[]):
        if unit.get("owned_by_package") is False:
            add("persistence", f"Unpackaged systemd unit: {unit.get('path')}", 6.8, 0.25, 0.68, 0.70)

    return candidates


def render_ml_tab():
    st.subheader("🎯 ML Vulnerability & Host Finding Prioritization")
    artifact = load_ml_artifact(str(MODEL_PATH))

    if artifact is None:
        st.warning(f"Pre-trained model `{MODEL_PATH}` not found.")
        st.info("Train and export the offline model first by running:")
        st.code("python ml/train_pipeline.py", language="bash")
        return

    model = artifact["model"]
    f_cols = artifact["feature_cols"]
    eval_m = artifact["metrics"]
    cve_lookup = artifact.get("cve_lookup", {})

    # 1. Offline Model Evaluation Metrics (handles both key naming conventions)
    train_n = eval_m.get("train_samples", eval_m.get("train_rows", 0))
    test_n = eval_m.get("test_samples", eval_m.get("test_rows", 0))
    imp_dict = eval_m.get("importances", eval_m.get("feature_importances", {}))

    metrics({
        "Model": "RandomForestClassifier",
        "Test Accuracy": f"{eval_m.get('accuracy', 0)}%",
        "ROC-AUC Score": eval_m.get("roc_auc", 0),
        "Train / Test Rows": f"{train_n} / {test_n}",
    })
    st.divider()

    col_main, col_side = st.columns([2.2, 1])

    with col_main:
        st.markdown("#### Ranked Host Findings (Scored by Offline ML Model)")
        candidates = extract_host_candidates()
        if not candidates:
            st.info("No risky findings extracted from `output/*.json` yet. Collect data first.")
        else:
            df_cand = pd.DataFrame(candidates)
            probs = model.predict_proba(df_cand[f_cols])[:, 1]
            df_cand["ML Risk Score"] = (probs * 100).round(2)
            df_cand.sort_values(by="ML Risk Score", ascending=False, inplace=True)
            df_cand.reset_index(drop=True, inplace=True)
            df_cand.insert(0, "Rank", df_cand.index + 1)

            st.dataframe(
                df_cand[["Rank", "ML Risk Score", "Module", "Finding", "CVE / Type", "cvss_base", "exposure_weight"]],
                hide_index=True,
                use_container_width=True,
                column_config={
                    "ML Risk Score": st.column_config.ProgressColumn(
                        "ML Risk Score (0-100)", format="%.1f%%", min_value=0, max_value=100
                    )
                },
            )

    with col_side:
        st.markdown("#### Feature Importances")
        imp_df = pd.DataFrame(
            list(imp_dict.items()), columns=["Feature", "Importance"]
        ).sort_values("Importance", ascending=True)
        st.bar_chart(imp_df.set_index("Feature"))

        st.markdown("#### Interactive CVE Scorer")
        cve_in = st.text_input("CVE ID (from local lookup)", value="CVE-2024-3094").strip().upper()
        info = cve_lookup.get(cve_in, {})
        default_cvss = float(info.get("cvss_base", 7.8))
        default_epss = float(info.get("epss_score", 0.15))
        default_pct = float(info.get("epss_percentile", 0.60))

        cvss_in = st.slider("CVSS Base Score", 0.0, 10.0, default_cvss, 0.1)
        epss_in = st.slider("EPSS Probability", 0.0, 1.0, default_epss, 0.01)
        exp_in = st.slider("Host Exposure Weight", 0.1, 1.0, 0.85, 0.05)

        X_single = pd.DataFrame([{
            "cvss_base": cvss_in,
            "epss_score": epss_in,
            "epss_percentile": default_pct if cve_in in cve_lookup else epss_in,
            "exposure_weight": exp_in,
        }])
        pred_score = model.predict_proba(X_single[f_cols])[0, 1] * 100
        st.metric("Predicted Exploitation Risk", f"{pred_score:.2f} / 100")
        if cve_in in cve_lookup:
            st.caption(f"Matched in local dataset · In CISA KEV: **{bool(info.get('is_exploited'))}**")
        else:
            st.caption("CVE not in local top-subset; using slider values.")

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
        st.cache_data.clear()
        st.rerun()
    st.markdown("**Full-coverage collection (recommended):**")
    st.code('sudo ./run_all.sh "$(which python)"          # add --fast to skip slow checks', language="bash")
    if warns:
        st.markdown("**Collector warnings**")
        show([{"collector": a, "warning": b} for a, b in warns])


tabs = st.tabs(["Overview", "🎯 ML Risk Ranking"] + [v["title"] for v in COLLECTORS.values()])
with tabs[0]:
    overview()
with tabs[1]:
    render_ml_tab()
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