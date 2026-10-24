from engine.core import rule, ev
from ._helpers import writable_by_others


@rule(id="SVC-001", title="Service runs files that non-root users can modify", category="weakness",
      severity="critical", confidence="high",
      why="If the unit file, a drop-in or the program a service starts is writable by others, they can make the service run their code with the service's privileges (root for most services).",
      fix="Restore ownership and mode from the package (pacman -Qkk <package>) and review the file contents for tampering before restarting the service.",
      requires={"services": ["services"]})
def svc_001(ctx):
    for s in ctx.d("services")["services"]:
        bad = []
        if writable_by_others(s.get("fragment_meta")):
            bad.append(("unit file", s["fragment_meta"]))
        bad += [("drop-in", m) for m in s.get("dropin_meta") or [] if writable_by_others(m)]
        bad += [("ExecStart binary", m) for m in s.get("exec_start") or [] if writable_by_others(m)]
        if bad:
            is_root = s.get("effective_user") == "root"
            ctx.fail(s["name"], [ev("services", f"services[{s['name']}]", f"{what} {m['path']} mode {m.get('mode')} group {m.get('group')}",
                                    "not writable by non-root users") for what, m in bad],
                     severity="critical" if is_root else "high", runs_as_root=is_root)


@rule(id="SVC-002", title="Root service runs a program no package owns", category="weakness", severity="medium",
      confidence="medium",
      why="A root-privileged service whose binary did not come from a package cannot be verified or patched through pacman, and is a natural place to hide or to leave an unpatched self-built tool.",
      fix="Confirm where the binary came from (build directory, sha256). If it is yours, allowlist by path and sha256 and track its updates manually.",
      requires={"services": ["services"]})
def svc_002(ctx):
    unknown = 0
    for s in ctx.d("services")["services"]:
        if s.get("sub") != "running" or s.get("effective_user") != "root":
            continue
        for e in s.get("exec_start") or []:
            if not e.get("exists"):
                continue
            own = e.get("owned_by_package")
            if own is None:
                unknown += 1
            elif own is False:
                ctx.fail(s["name"], [ev("services", f"services[{s['name']}].exec_start", f"{e['path']} (no owning package)", "owned by a package")],
                         attrs={"path": e["path"]}, runs_as_root=True)
    if unknown:
        ctx.partial(f"{unknown} ExecStart binaries have unknown package ownership (pacman unavailable)")
