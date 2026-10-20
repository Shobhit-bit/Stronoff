#!/usr/bin/env python3
"""Network collector (Arch Linux first).

Collects FACTS (no verdicts) about:
  - listening TCP sockets and bound UDP sockets: address, port, scope
    (loopback / all_interfaces / private / link_local / public), owning process
  - established/other TCP connections (remote address, owning process)
  - interfaces: addresses, up/down, MTU, PROMISCUOUS flag, wireless
  - DNS resolvers from /etc/resolv.conf
  - firewall state across nftables, iptables, ufw, firewalld: default policies,
    base chains + rule counts, whether the service that restores rules at boot is enabled
  - permissions of privileged local sockets (docker.sock, libvirt, ...)

PRIVACY NOTE: connection lists contain remote IP addresses. Treat the JSON as sensitive.

Usage:
  sudo python -m collectors.network --out network.json --pretty
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
from collections import Counter, defaultdict

import psutil

from .common import new_result, read_lines, file_meta, emit, classify_addr

MAX_CONNS = 300
MAX_RAW = 20000
SPECIAL_SOCKETS = [
    "/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock",
    "/run/libvirt/libvirt-sock", "/run/dbus/system_bus_socket", "/run/containerd/containerd.sock",
]
FW_SERVICES = ["nftables.service", "iptables.service", "ip6tables.service",
               "ufw.service", "firewalld.service"]


def run(cmd, timeout=30):
    env = dict(os.environ, LC_ALL="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


# ---------- helpers ----------

_proc_cache: dict = {}


def proc_info(pid: int | None) -> dict:
    if pid is None:
        return {"pid": None, "process": None, "exe": None, "user": None}
    if pid not in _proc_cache:
        info = {"pid": pid, "process": None, "exe": None, "user": None}
        try:
            p = psutil.Process(pid)
            info["process"] = p.name()
            for key, fn in (("exe", p.exe), ("user", p.username)):
                try:
                    info[key] = fn()
                except (psutil.AccessDenied, KeyError):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        _proc_cache[pid] = info
    return _proc_cache[pid]


def collect_sockets(result: dict) -> dict:
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        result["errors"].append({"cmd": "net_connections", "error": "access_denied"})
        return {"listening": [], "connections": {}}

    listening, established, status_counts = [], [], Counter()
    for c in conns:
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        ver = 6 if c.family == socket.AF_INET6 else 4
        lip, lport = (c.laddr.ip, c.laddr.port) if c.laddr else (None, None)
        has_remote = bool(c.raddr)
        status_counts[f"{proto}:{c.status}"] += 1

        is_listen = (proto == "tcp" and c.status == "LISTEN") or (proto == "udp" and not has_remote)
        if is_listen:
            listening.append({
                "proto": proto, "ip_version": ver,
                "state": "listening" if proto == "tcp" else "bound",
                "address": lip, "port": lport,
                "scope": classify_addr(lip),
                **proc_info(c.pid),
            })
        elif has_remote and proto == "tcp":
            established.append({
                "proto": proto, "ip_version": ver, "state": c.status,
                "local_address": lip, "local_port": lport,
                "remote_address": c.raddr.ip, "remote_port": c.raddr.port,
                "remote_scope": classify_addr(c.raddr.ip),
                **proc_info(c.pid),
            })
    listening.sort(key=lambda x: (x["proto"], x["port"] or 0))
    return {
        "listening": listening,
        "connections": {
            "by_status": dict(status_counts),
            "total_remote_tcp": len(established),
            "list": established[:MAX_CONNS],
            "truncated": len(established) > MAX_CONNS,
        },
    }


def collect_interfaces() -> list[dict]:
    fam = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6", psutil.AF_LINK: "mac"}
    stats = psutil.net_if_stats()
    out = []
    for name, addrs in psutil.net_if_addrs().items():
        flags = 0
        try:
            with open(f"/sys/class/net/{name}/flags") as f:
                flags = int(f.read().strip(), 16)
        except (OSError, ValueError):
            pass
        st = stats.get(name)
        out.append({
            "name": name,
            "up": st.isup if st else None,
            "mtu": st.mtu if st else None,
            "promiscuous": bool(flags & 0x100) if flags else None,
            "wireless": os.path.isdir(f"/sys/class/net/{name}/wireless"),
            "addresses": [{"family": fam.get(a.family, str(a.family)),
                           "address": a.address.split("%")[0], "netmask": a.netmask}
                          for a in addrs if a.family in fam],
        })
    return out


# ---------- firewall ----------

def parse_nft_json(text: str) -> dict:
    items = json.loads(text).get("nftables", [])
    tables, chains = [], []
    rule_counts: dict = defaultdict(int)
    for it in items:
        if "table" in it:
            t = it["table"]
            tables.append({"family": t.get("family"), "name": t.get("name")})
        elif "chain" in it:
            c = it["chain"]
            chains.append({"family": c.get("family"), "table": c.get("table"), "name": c.get("name"),
                           "hook": c.get("hook"), "type": c.get("type"),
                           "priority": c.get("prio"), "policy": c.get("policy")})
        elif "rule" in it:
            r = it["rule"]
            rule_counts[(r.get("family"), r.get("table"), r.get("chain"))] += 1
    for c in chains:
        c["rule_count"] = rule_counts.get((c["family"], c["table"], c["name"]), 0)
    base = [c for c in chains if c["hook"]]
    return {"tables": tables, "base_chains": base,
            "total_chains": len(chains), "total_rules": sum(rule_counts.values())}


def parse_iptables_S(text: str) -> dict:
    policies, rules = {}, 0
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "-P":
            policies[p[1]] = p[2]
        elif p and p[0] == "-A":
            rules += 1
    return {"policies": policies, "rule_count": rules}


def parse_ufw(text: str) -> dict:
    status = re.search(r"^Status:\s*(\S+)", text, re.M)
    default = re.search(r"^Default:\s*(.+)$", text, re.M)
    defaults = {}
    if default:
        for m in re.finditer(r"(\w+)\s+\((\w+)\)", default.group(1)):
            defaults[m.group(2)] = m.group(1)          # {'incoming': 'deny', ...}
    return {"status": status.group(1) if status else None, "defaults": defaults}


def svc_state(unit: str) -> dict:
    if not shutil.which("systemctl"):
        return {"enabled": None, "active": None}
    return {"enabled": run(["systemctl", "is-enabled", unit])[1].strip() or None,
            "active": run(["systemctl", "is-active", unit])[1].strip() or None}


def collect_firewall(result: dict) -> dict:
    fw: dict = {"frameworks_present": [], "nftables": None, "iptables": None,
                "ufw": None, "firewalld": None}
    denied = False

    if shutil.which("nft"):
        fw["frameworks_present"].append("nftables")
        rc, out, err = run(["nft", "-j", "list", "ruleset"])
        if rc == 0:
            try:
                fw["nftables"] = {"readable": True, **parse_nft_json(out)}
                rc2, txt, _ = run(["nft", "list", "ruleset"])
                fw["nftables"]["ruleset_text"] = txt[:MAX_RAW] if rc2 == 0 else None
            except (json.JSONDecodeError, TypeError, AttributeError) as e:
                fw["nftables"] = {"readable": False, "error": f"parse: {e}"}
        else:
            denied = denied or "Operation not permitted" in err or "Permission" in err
            fw["nftables"] = {"readable": False, "error": err.strip()[:150]}

    if shutil.which("iptables"):
        fw["frameworks_present"].append("iptables")
        ipt = {}
        for tool in ("iptables", "ip6tables"):
            if not shutil.which(tool):
                continue
            ver = run([tool, "--version"])[1].strip()
            rc, out, err = run([tool, "-S"])
            if rc == 0:
                ipt[tool] = {"readable": True, "version": ver, **parse_iptables_S(out)}
            else:
                denied = denied or "ermission" in err or "not permitted" in err
                ipt[tool] = {"readable": False, "version": ver, "error": err.strip()[:150]}
        fw["iptables"] = ipt

    if shutil.which("ufw"):
        fw["frameworks_present"].append("ufw")
        rc, out, err = run(["ufw", "status", "verbose"])
        fw["ufw"] = ({"readable": True, **parse_ufw(out), "raw": out[:4000]} if rc == 0
                     else {"readable": False, "error": (err or out).strip()[:150]})

    if shutil.which("firewall-cmd"):
        fw["frameworks_present"].append("firewalld")
        rc, out, _ = run(["firewall-cmd", "--state"])
        zone = run(["firewall-cmd", "--get-default-zone"])[1].strip() if rc == 0 else None
        fw["firewalld"] = {"state": out.strip() or "not running", "default_zone": zone}

    fw["services"] = {u: svc_state(u) for u in FW_SERVICES}
    fw["nftables_conf_meta"] = file_meta("/etc/nftables.conf")
    if denied:
        result["warnings"].append("Firewall rules unreadable (needs root): firewall state is UNKNOWN, not 'open'.")
    if not fw["frameworks_present"]:
        result["warnings"].append("No firewall tooling installed (nft/iptables/ufw/firewalld).")
    return fw


# ---------- main ----------

def collect() -> dict:
    result = new_result("network")
    if not result["ran_as_root"]:
        result["warnings"].append(
            "Not root: process info for other users' sockets and firewall rules are missing.")

    sockets = collect_sockets(result)
    listening = sockets["listening"]
    tcp = [s for s in listening if s["proto"] == "tcp"]
    ns = []
    for line in read_lines("/etc/resolv.conf", result):
        m = re.match(r"^\s*nameserver\s+(\S+)", line)
        if m:
            ns.append({"address": m.group(1), "scope": classify_addr(m.group(1))})

    result["data"] = {
        "listening": listening,
        "connections": sockets["connections"],
        "interfaces": collect_interfaces(),
        "dns": {"nameservers": ns, "resolv_conf_meta": file_meta("/etc/resolv.conf")},
        "firewall": collect_firewall(result),
        "special_sockets": [m for m in map(file_meta, SPECIAL_SOCKETS) if m.get("exists")],
        "counts": {
            "listening_total": len(listening),
            "tcp_listening": len(tcp),
            "tcp_all_interfaces": sum(s["scope"] == "all_interfaces" for s in tcp),
            "tcp_loopback_only": sum(s["scope"] == "loopback" for s in tcp),
            "udp_bound": sum(s["proto"] == "udp" for s in listening),
            "listening_pid_unknown": sum(s["pid"] is None for s in listening),
            "promiscuous_interfaces": sum(bool(i["promiscuous"]) for i in collect_interfaces()),
        },
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="Collect network facts (no judgments).")
    ap.add_argument("--out")
    ap.add_argument("--pretty", action="store_true")
    a = ap.parse_args()
    emit(collect(), a.out, a.pretty)


if __name__ == "__main__":
    main()
