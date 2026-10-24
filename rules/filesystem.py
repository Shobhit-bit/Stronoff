from engine.core import rule, ev
from ._helpers import under, writable_by_others

_FS = {"filesystem": ["suid_files", "sgid_files"]}


def _files(ctx):
    d = ctx.d("filesystem")
    if any((d.get("scan") or {}).get("truncated", {}).values()):
        ctx.note("some file lists were capped; the true totals are in filesystem.totals")
    return d["suid_files"] + d["sgid_files"]


def _rec_ev(path_name, f, expected):
    return ev("filesystem", path_name, f"mode {f.get('mode')} owner {f.get('owner')} pkg {f.get('package')}", expected)


@rule(id="FS-001", title="SUID/SGID file not owned by any package", category="weakness", severity="high",
      confidence="medium",
      why="SUID/SGID programs run with their owner's privileges. One that no package installed was added locally and cannot be updated or verified by pacman.",
      fix="Check where it came from (pacman -Qo, build history, sha256). If you built it yourself, allowlist it by path and sha256; if unknown, investigate before removing the bit (chmod u-s) or the file.",
      requires=_FS)
def fs_001(ctx):
    unknown = 0
    for f in _files(ctx):
        if under(f["path"], ctx.th("user_writable_prefixes")):
            continue                                   # FS-002 handles these
        own = f.get("owned_by_package")
        if own is None:
            unknown += 1
        elif own is False:
            ctx.fail(f["path"], [_rec_ev("suid_files/sgid_files", f, "owned by a package")],
                     attrs={"sha256": f.get("sha256")}, runs_as_root=f.get("owner") == "root")
    if unknown:
        ctx.partial(f"{unknown} SUID/SGID file(s) have unknown package ownership (pacman unavailable)")


@rule(id="FS-002", title="SUID/SGID file in a user-writable location", category="weakness", severity="high",
      confidence="high",
      why="A SUID/SGID file under /tmp, /home or similar can be created or replaced by ordinary users, which is a direct privilege-escalation path.",
      fix="Identify the file's origin first. Unless you deliberately put it there, remove the SUID/SGID bit or the file, and review how it got there.",
      requires=_FS)
def fs_002(ctx):
    for f in _files(ctx):
        if under(f["path"], ctx.th("user_writable_prefixes")):
            ctx.fail(f["path"], [_rec_ev("suid_files/sgid_files", f, "no SUID/SGID files in user-writable dirs")],
                     attrs={"sha256": f.get("sha256")}, runs_as_root=f.get("owner") == "root")


@rule(id="FS-003", title="World-writable file or directory without sticky bit", category="weakness",
      severity="medium", confidence="high",
      why="Anyone on the machine can modify it. In system directories that means code or configuration anyone can tamper with.",
      fix="Check whether the permissive mode is intentional (Wine prefixes, shared build dirs). Otherwise tighten it (e.g. chmod o-w) after confirming nothing depends on it.",
      requires={"filesystem": ["world_writable_files", "world_writable_dirs_no_sticky", "scan"]})
def fs_003(ctx):
    d = ctx.d("filesystem")
    for kind, key in (("file", "world_writable_files"), ("directory (no sticky bit)", "world_writable_dirs_no_sticky")):
        for f in d[key]:
            sev = "high" if under(f["path"], ctx.th("system_dirs")) else "medium"
            ctx.fail(f["path"], [_rec_ev(key, f, f"{kind} not world-writable")], severity=sev)
    denied = (d["scan"] or {}).get("denied_dirs", 0)
    if denied:
        ctx.partial(f"scan incomplete: {denied} directories were unreadable (run as root)")


@rule(id="FS-004", title="Security-critical file writable or readable by the wrong users", category="weakness",
      severity="high", confidence="high",
      why="Files like /etc/passwd, shadow, sudoers and sshd_config control authentication. If others can write them (or read the password hashes), the machine's access control is broken.",
      fix="Compare against the packaged mode (pacman -Qkk <package>) and restore it, e.g. chmod 600 /etc/shadow, after checking for tampering.",
      requires={"filesystem": ["sensitive_paths"]}, optional=("accounts",))
def fs_004(ctx):
    metas = {m["path"]: m for m in ctx.d("filesystem")["sensitive_paths"]}
    for m in ctx.get("accounts", "account_file_meta", []):
        metas.setdefault(m["path"], m)
    sensitive, acct = set(ctx.th("sensitive_files")), set(ctx.th("critical_account_files"))
    for path, m in sorted(metas.items()):
        if path not in sensitive:
            continue
        if m.get("exists") is None:
            ctx.partial(f"{path}: permissions unreadable")
            continue
        if not m.get("exists"):
            continue
        problems, sev = [], "high"
        if path in ("/etc/shadow", "/etc/gshadow") and m.get("world_readable"):
            problems.append("readable by everyone"); sev = "critical"
        if writable_by_others(m):
            problems.append("writable by users other than root")
            if path in acct:
                sev = "critical"
        if problems:
            ctx.fail(path, [ev("filesystem", "sensitive_paths", f"mode {m.get('mode')} {m.get('owner')}:{m.get('group')}: "
                                                              + ", ".join(problems), "root-owned, not writable by others")],
                     severity=sev)
