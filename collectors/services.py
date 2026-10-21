#!/usr/bin/env python3
"""Services collector (Arch Linux / systemd).

Collects FACTS about systemd service and socket units:
  - unit-file state (enabled/disabled/static/masked/...) and preset
  - runtime state (active/sub), MainPID, effective user
  - where the unit file lives, its drop-ins, permissions, owning package
  - ExecStart binaries (+ permissions, owning package)
  - sandboxing properties (NoNewPrivileges, ProtectSystem, ...)
  - `systemd-analyze security` exposure score per service
  - socket units and what they listen on

Without a running systemd (containers, chroots) only the unit-file list is
collected; the report says so instead of pretending the rest is clean.
User-level units (systemctl --user, e.g. your Hyprland session) are NOT covered
here; they belong with the persistence collector.

Usage:
  sudo python -m collectors.services --out services.json --pretty
  python -m collectors.services --no-analyze        # skip the (slow) security scores
"""
import argparse
import json
import os
import re
import shutil
import subprocess

from .common import new_result, emit, file_meta, pacman_owners

SERVICE_PROPS = [
    "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath",
    "DropInPaths", "MainPID", "User", "Group", "DynamicUser", "ExecStart",
    "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "ProtectSystem", "ProtectHome",
    "CapabilityBoundingSet", "AmbientCapabilities",
]
SOCKET_PROPS = ["Id", "ActiveState", "SubState", "FragmentPath", "Listen", "Accept", "SocketMode"]
BATCH = 40
MAX_CAPSTR = 600


def run(cmd: list[str], timeout: int = 60):
    env = dict(os.environ, LC_ALL="C", SYSTEMD_COLORS="0", SYSTEMD_PAGER="")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


# ---------- parsers (pure functions, unit-testable on saved text) ----------

def parse_unit_files(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 2:
            out.append({"name": f[0], "state": f[1], "preset": f[2] if len(f) > 2 else None})
    return out


def parse_list_units(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        f = line.split(None, 4)
        if len(f) >= 4:
            out.append({"name": f[0], "load": f[1], "active": f[2], "sub": f[3]})
    return out


def parse_show(text: str) -> dict[str, dict]:
    """`systemctl show` for several units -> {unit_id: {prop: value | [values]}}.
    Repeated keys (e.g. Listen=) become lists."""
    units = {}
    for block in text.strip().split("\n\n"):
        props: dict = {}
        for line in block.splitlines():
            k, sep, v = line.partition("=")
            if not sep:
                continue
            if k in props:
                if not isinstance(props[k], list):
                    props[k] = [props[k]]
                props[k].append(v)
            else:
                props[k] = v
        if "Id" in props:
            units[props["Id"]] = props
    return units


def exec_paths(value) -> list[str]:
    """ExecStart={ path=/usr/bin/x ; argv[]=... ; ... } -> ['/usr/bin/x'].
    Arguments (argv) are deliberately dropped: they can contain secrets."""
    if not value:
        return []
    vals = value if isinstance(value, list) else [value]
    paths = []
    for v in vals:
        paths += re.findall(r"path=([^ ;]+)", v)
    return paths


def parse_analyze(text: str) -> dict[str, dict]:
    """systemd-analyze security overview -> {unit: {exposure, predicate}} (JSON or table)."""
    out = {}
    try:
        for item in json.loads(text):
            unit = item.get("unit")
            if unit:
                out[unit] = {"exposure": item.get("exposure"), "predicate": item.get("predicate")}
        if out:
            return out
    except (json.JSONDecodeError, AttributeError, TypeError):
        pass
    for line in text.splitlines():
        m = re.match(r"^\W*(\S+\.service)\s+(\d+(?:\.\d+)?)\s+(\S+)", line)
        if m:
            out[m.group(1)] = {"exposure": float(m.group(2)), "predicate": m.group(3)}
    return out


def _yes(v):
    return None if v in (None, "") else v == "yes"


def _short(v):
    if v is None:
        return None
    return v if len(v) <= MAX_CAPSTR else v[:MAX_CAPSTR] + "...[truncated]"


# ---------- collection ----------

def _show_all(units: list[str], props: list[str]) -> dict[str, dict]:
    got = {}
    for i in range(0, len(units), BATCH):
        chunk = units[i:i + BATCH]
        rc, out, _ = run(["systemctl", "show", "--no-pager", "-p", ",".join(props), *chunk])
        if rc == 0:
            got.update(parse_show(out))
    return got


def collect(do_analyze=True) -> dict:
    result = new_result("services")
    if not shutil.which("systemctl"):
        result["warnings"].append("systemctl not found: not a systemd system.")
        result["data"] = {"systemd_available": False}
        return result

    rc, out, _ = run(["systemctl", "--version"])
    m = re.match(r"systemd (\d+)", out)
    version = int(m.group(1)) if m else None

    rc, out, err = run(["systemctl", "list-unit-files", "--type=service,socket",
                        "--no-legend", "--no-pager"])
    if rc != 0:
        result["errors"].append({"cmd": "list-unit-files", "error": err.strip()[:200]})
    unit_files = parse_unit_files(out)

    running = os.path.isdir("/run/systemd/system")
    data = {
        "systemd_available": True,
        "systemd_version": version,
        "manager_running": running,
        "unit_files": unit_files,
        "unit_file_state_counts": {},
    }
    for u in unit_files:
        data["unit_file_state_counts"][u["state"]] = data["unit_file_state_counts"].get(u["state"], 0) + 1

    if not running:
        result["warnings"].append(
            "systemd is not the running init (container/chroot): only unit-file states "
            "collected; runtime state, hardening and exposure scores are MISSING.")
        result["data"] = data
        return result
    if not result["ran_as_root"]:
        result["warnings"].append("Not root: some unit properties/exposure data may be incomplete.")

    rc, out, err = run(["systemctl", "list-units", "--type=service,socket", "--all",
                        "--no-legend", "--no-pager", "--plain"])
    if rc != 0:
        result["errors"].append({"cmd": "list-units", "error": err.strip()[:200]})
    runtime = parse_list_units(out)
    loaded = [u for u in runtime if u["load"] != "not-found"]
    svc_names = [u["name"] for u in loaded if u["name"].endswith(".service")]
    sock_names = [u["name"] for u in loaded if u["name"].endswith(".socket")]

    props = _show_all(svc_names, SERVICE_PROPS)
    sprops = _show_all(sock_names, SOCKET_PROPS)

    scores = {}
    if do_analyze:
        if version and version >= 250:
            rc, out, err = run(["systemd-analyze", "security", "--no-pager", "--json=short"], timeout=300)
        else:
            rc, out, err = run(["systemd-analyze", "security", "--no-pager"], timeout=300)
        if rc == 0:
            scores = parse_analyze(out)
        else:
            result["warnings"].append(f"systemd-analyze security failed: {err.strip()[:120]}")

    # Ownership lookup for unit files and ExecStart binaries (one batched call)
    all_paths = set()
    for p in props.values():
        if p.get("FragmentPath"):
            all_paths.add(p["FragmentPath"])
        all_paths.update(exec_paths(p.get("ExecStart")))
    owners = pacman_owners(sorted(all_paths))
    if owners is None:
        result["warnings"].append("pacman not available: package ownership not checked.")

    def pkg(path):
        if owners is None or not path:
            return None, None
        info = owners.get(path)
        return (info["package"] if info else None), info is not None

    state_by_name = {u["name"]: u for u in unit_files}
    rt_by_name = {u["name"]: u for u in runtime}
    services = []
    for name in svc_names:
        p = props.get(name, {})
        frag = p.get("FragmentPath") or None
        dropins = [d for d in (p.get("DropInPaths") or "").split() if d]
        user = p.get("User") or None
        dyn = _yes(p.get("DynamicUser"))
        frag_pkg, frag_owned = pkg(frag)
        ex = []
        for path in exec_paths(p.get("ExecStart")):
            meta = file_meta(path)
            meta["package"], meta["owned_by_package"] = pkg(path)
            ex.append(meta)
        sc = scores.get(name, {})
        services.append({
            "name": name,
            "load": rt_by_name[name]["load"],
            "active": p.get("ActiveState") or rt_by_name[name]["active"],
            "sub": p.get("SubState") or rt_by_name[name]["sub"],
            "unit_file_state": p.get("UnitFileState") or state_by_name.get(name, {}).get("state"),
            "preset": state_by_name.get(name, {}).get("preset"),
            "main_pid": int(p["MainPID"]) if p.get("MainPID", "").isdigit() and p["MainPID"] != "0" else None,
            "user": user,
            "dynamic_user": dyn,
            "effective_user": user or ("(dynamic)" if dyn else "root"),
            "group": p.get("Group") or None,
            "fragment_path": frag,
            "fragment_meta": file_meta(frag) if frag else None,
            "fragment_package": frag_pkg,
            "fragment_owned_by_package": frag_owned,
            "dropins": dropins,
            "dropin_meta": [file_meta(d) for d in dropins],
            "exec_start": ex,
            "hardening": {
                "no_new_privileges": _yes(p.get("NoNewPrivileges")),
                "private_tmp": _yes(p.get("PrivateTmp")),
                "private_devices": _yes(p.get("PrivateDevices")),
                "protect_system": p.get("ProtectSystem") or None,
                "protect_home": p.get("ProtectHome") or None,
                "capability_bounding_set": _short(p.get("CapabilityBoundingSet")),
                "ambient_capabilities": _short(p.get("AmbientCapabilities")) or None,
            },
            "security_exposure": sc.get("exposure"),
            "security_predicate": sc.get("predicate"),
        })

    sockets = []
    for name in sock_names:
        p = sprops.get(name, {})
        listen = p.get("Listen", [])
        sockets.append({
            "name": name,
            "active": p.get("ActiveState"),
            "sub": p.get("SubState"),
            "unit_file_state": state_by_name.get(name, {}).get("state"),
            "fragment_path": p.get("FragmentPath") or None,
            "listen": [listen] if isinstance(listen, str) and listen else listen,
            "accept": _yes(p.get("Accept")),
            "socket_mode": p.get("SocketMode") or None,
        })

    rc, out, _ = run(["systemctl", "get-default"])
    data.update({
        "default_target": out.strip() or None,
        "system_state": run(["systemctl", "is-system-running"])[1].strip() or None,
        "services": services,
        "sockets": sockets,
        "failed_units": [u["name"] for u in runtime if u["active"] == "failed"],
        "security_scores_collected": bool(scores),
        "counts": {
            "services_loaded": len(services),
            "services_running": sum(s["sub"] == "running" for s in services),
            "services_enabled": sum(s["unit_file_state"] == "enabled" for s in services),
            "services_running_as_root": sum(s["effective_user"] == "root" and s["sub"] == "running" for s in services),
            "sockets_loaded": len(sockets),
        },
    })
    result["data"] = data
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect systemd service facts (no judgments).")
    ap.add_argument("--no-analyze", action="store_true", help="skip systemd-analyze security")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(not a.no_analyze), a.out, a.pretty)


if __name__ == "__main__":
    main()
