from engine.core import rule, ev
from ._helpers import firewall_state, nonloopback_listeners
from engine.core import Unknown


@rule(id="NET-001", title="Known-risky service listens beyond loopback", category="exposure", severity="high",
      confidence="high",
      why="Services like telnet, SMB, NFS, Docker's TCP API and databases are frequent attack targets and are rarely meant to be reachable from other machines.",
      fix="Bind the service to 127.0.0.1 (or a management interface) in its config, or stop and disable it. Verify what depends on it first.",
      requires={"network": ["listening"]})
def net_001(ctx):
    risky, crit = set(ctx.th("risky_ports")), set(ctx.th("critical_ports"))
    groups = {}
    for l in ctx.d("network")["listening"]:
        if l.get("scope") != "loopback" and l.get("port") in risky:
            groups.setdefault((l["proto"], l["port"]), []).append(l)
    for (proto, port), ls in groups.items():
        l = ls[0]
        ctx.fail(f"{proto}/{port}", [ev("network", "listening[]", f"{l['proto']} {l['address']}:{l['port']} scope {l['scope']} process {l.get('process')} user {l.get('user')}",
                                       "loopback only")],
                 severity="critical" if port in crit else "high", exposed=True, runs_as_root=l.get("user") == "root")


@rule(id="NET-002", title="Network-reachable listeners and no packet filtering", category="exposure",
      severity="medium", confidence="medium",
      why="Services reachable beyond loopback with no firewall rules rely entirely on each service being secure and correctly bound.",
      fix="Enable a default-deny inbound firewall (nftables or ufw) that allows only what you need, and make sure it starts at boot.",
      requires={"network": ["listening", "firewall"]})
def net_002(ctx):
    ls = nonloopback_listeners(ctx)
    if not ls:
        return
    state, det = firewall_state(ctx)
    if state == "filtering":
        return
    if state == "unknown":
        raise Unknown(f"firewall rules unreadable ({', '.join(det)}): run the network collector as root")
    risky = set(ctx.th("risky_ports"))
    sample = [f"{l['proto']}/{l['port']} {l.get('process')}" for l in ls[:5]]
    ctx.fail("host firewall", [ev("network", "firewall", f"no active input filtering (frameworks present: {det or 'none'})", "default-deny inbound"),
                               ev("network", "listening[]", f"{len(ls)} non-loopback listener(s), e.g. {sample}", "")],
             severity="high" if any(l.get("port") in risky for l in ls) else "medium", exposed=True)


@rule(id="NET-003", title="Privileged local socket accessible to everyone", category="weakness", severity="critical",
      confidence="high",
      why="Access to the Docker, containerd or libvirt socket is equivalent to root. A world-writable socket gives that to every local user.",
      fix="Restrict the socket to root and a small trusted group (e.g. mode 660 owner root group docker) and review who is in that group.",
      requires={"network": ["special_sockets"]})
def net_003(ctx):
    for m in ctx.d("network")["special_sockets"]:
        if m.get("world_writable"):
            ctx.fail(m["path"], [ev("network", "special_sockets", f"mode {m.get('mode')} {m.get('owner')}:{m.get('group')}", "not world-writable")],
                     runs_as_root=True)
