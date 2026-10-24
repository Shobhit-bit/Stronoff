from engine.core import rule, ev
from ._helpers import user_procs, suspicious_exec


@rule(id="X-001", title="Outbound connection from a suspicious process", category="ioc", severity="high",
      confidence="medium",
      why="A process running from memory, a temp directory, or a deleted binary that is talking to a public address is the classic shape of malware beaconing or exfiltrating.",
      fix="Identify the process (ls -l /proc/<pid>/exe, ss -tnp), capture it for analysis if you can, then isolate the machine from the network if it is not recognisable.",
      requires={"network": ["connections"], "processes": ["processes"]})
def x_001(ctx):
    conns = ctx.d("network")["connections"].get("list") or []
    procs = {p["pid"]: p for p in user_procs(ctx)}
    no_pid = 0
    for c in conns:
        if c.get("remote_scope") != "public":
            continue
        if c.get("pid") is None:
            no_pid += 1
            continue
        p = procs.get(c["pid"])
        if not p or p["name"] != c.get("process"):           # pid reused between the two collector runs
            continue
        why = suspicious_exec(p, ctx)
        if why:
            ctx.fail(f"{p.get('exe') or p['name']} -> {c['remote_address']}:{c['remote_port']}",
                     [ev("network", "connections.list[]", f"pid {p['pid']} {why}; connection to {c['remote_address']}:{c['remote_port']}",
                         "no suspicious executable talking to public hosts")],
                     exposed=True, runs_as_root=p.get("user") == "root")
    if no_pid:
        ctx.partial(f"{no_pid} public connection(s) have no owning PID (network collector ran without root)")
