from engine.core import rule, ev, Unknown, NotApplicable
from ._helpers import ssh_effective, one, sshd_reachability

_SSH = {"configs": ["ssh"]}


def _latent(reachable):
    return reachable is False


@rule(id="CFG-001", title="sshd allows root login", category="weakness", severity="high", confidence="high",
      why="Root is the most targeted account. Allowing it to log in over SSH means a single guessed or leaked credential gives full control.",
      fix="Set PermitRootLogin no (or prohibit-password with keys only) in /etc/ssh/sshd_config.d/ and reload sshd. Keep a working non-root login first.",
      requires=_SSH, needs_root=("configs",))
def cfg_001(ctx):
    eff = ssh_effective(ctx)
    if str(one(eff.get("permitrootlogin"))).lower() == "yes":
        reachable, _ = sshd_reachability(ctx)
        ctx.fail("sshd PermitRootLogin", [ev("configs", "ssh.effective.permitrootlogin", "yes", "no or prohibit-password")],
                 severity="low" if _latent(reachable) else "high", exposed=reachable is not False,
                 why="PermitRootLogin yes is set, but sshd is not enabled or listening, so this is latent until sshd is started."
                 if _latent(reachable) else None)


@rule(id="CFG-002", title="sshd allows empty passwords", category="weakness", severity="critical", confidence="high",
      why="With PermitEmptyPasswords yes, accounts with an empty password can log in over SSH with no credential at all.",
      fix="Set PermitEmptyPasswords no and make sure no account has an empty password (see ACC-002).",
      requires=_SSH, needs_root=("configs",))
def cfg_002(ctx):
    eff = ssh_effective(ctx)
    if str(one(eff.get("permitemptypasswords"))).lower() == "yes":
        reachable, _ = sshd_reachability(ctx)
        ctx.fail("sshd PermitEmptyPasswords", [ev("configs", "ssh.effective.permitemptypasswords", "yes", "no"),
                                              ev("services", "sshd", "sshd not currently enabled or listening" if _latent(reachable) else "sshd reachable", "")],
                 exposed=reachable is not False)


@rule(id="CFG-003", title="sshd password authentication enabled while reachable", category="exposure",
      severity="medium", confidence="high",
      why="Password login can be guessed or sprayed from anywhere sshd is reachable; keys cannot.",
      fix="Use key-based login, then set PasswordAuthentication no. Test a key login in a second session before reloading sshd.",
      requires=_SSH, needs_root=("configs",), optional=("services", "network"))
def cfg_003(ctx):
    eff = ssh_effective(ctx)
    if str(one(eff.get("passwordauthentication"))).lower() != "yes":
        return
    reachable, loopback_only = sshd_reachability(ctx)
    if reachable is False:
        return
    evid = [ev("configs", "ssh.effective.passwordauthentication", "yes", "no")]
    if ctx.get("configs", "ssh.match_blocks", 0):
        evid.append(ev("configs", "ssh.match_blocks", ctx.get("configs", "ssh.match_blocks"),
                       "note: sshd -T does not evaluate Match blocks, which may override this"))
    if reachable is None:
        evid.append(ev("services", "sshd", "reachability unknown (services/network not collected)", ""))
    ctx.fail("sshd PasswordAuthentication", evid, severity="low" if loopback_only else "medium",
             exposed=not loopback_only)


def _sudo(ctx):
    s = ctx.d("configs").get("sudoers")
    if s is None:
        raise Unknown("configs.sudoers section missing (section failed)")
    if not s.get("installed", True):
        raise NotApplicable("sudo not installed")
    if not s.get("readable"):
        raise Unknown("/etc/sudoers unreadable (needs root)")
    return s


@rule(id="CFG-004", title="sudo grants passwordless or wildcard root access", category="weakness", severity="high",
      confidence="medium",
      why="NOPASSWD with ALL commands means anyone who gets that user's session becomes root with no further barrier. Wildcards in allowed commands are a well-known escalation trick.",
      fix="Verify with 'sudo -ll -U <user>' (the parser here is a heuristic). Restrict to specific commands and require a password where practical.",
      requires={"configs": ["sudoers"]}, needs_root=("configs",))
def cfg_004(ctx):
    for e in _sudo(ctx).get("entries", []):
        if e.get("type") != "userspec":
            continue
        runas = e.get("runas")
        root_capable = runas is None or e.get("runas_all") or "root" in str(runas).split(":")[0].split(",")
        who = ", ".join(e.get("who", []))
        subj = f"{who} ({e['file']}:{e['line']})"
        if e.get("nopasswd") and e.get("runs_all_commands") and root_capable:
            ctx.fail(subj, [ev("configs", "sudoers.entries", e["raw"], "no NOPASSWD ALL")], severity="high", runs_as_root=True)
        elif e.get("has_wildcard_command"):
            ctx.fail(subj, [ev("configs", "sudoers.entries", e["raw"], "no wildcard commands")], severity="medium",
                     why="A wildcard in an allowed sudo command can usually be abused to run arbitrary commands.")


@rule(id="CFG-005", title="sudo defaults or sudoers file permissions weaken protection", category="weakness",
      severity="high", confidence="high",
      why="Disabling authentication or env_reset, keeping LD_* variables, or letting others write sudoers files undermines the whole sudo barrier. Ignored drop-ins mean a rule you think exists does nothing.",
      fix="Remove the dangerous Defaults, set sudoers files to mode 0440 owned by root, and rename ignored drop-ins (no dots or trailing ~) with visudo.",
      requires={"configs": ["sudoers"]}, needs_root=("configs",))
def cfg_005(ctx):
    s = _sudo(ctx)
    d = s.get("global_defaults") or {}
    if d.get("authenticate") is False:
        ctx.fail("sudoers Defaults !authenticate", [ev("configs", "sudoers.global_defaults.authenticate", False, "authentication required")], runs_as_root=True)
    if d.get("env_reset") is False:
        ctx.fail("sudoers Defaults !env_reset", [ev("configs", "sudoers.global_defaults.env_reset", False, "env_reset on")], runs_as_root=True)
    keep = str(d.get("env_keep", ""))
    bad = [v for v in ctx.th("sudo_dangerous_env_keep") if v in keep]
    if bad:
        ctx.fail("sudoers Defaults env_keep", [ev("configs", "sudoers.global_defaults.env_keep", keep, f"must not keep {bad}")], runs_as_root=True)
    for fm in s.get("files", []):
        writable = fm.get("world_writable") or fm.get("group_writable")
        if writable or fm.get("mode") not in ("0440", "0400"):
            ctx.fail(fm["path"], [ev("configs", "sudoers.files", f"mode {fm.get('mode')} {fm.get('owner')}:{fm.get('group')}", "0440 root:root")],
                     runs_as_root=True)
    for p in s.get("ignored_files", []):
        ctx.fail(p, [ev("configs", "sudoers.ignored_files", p, "name without '.' or '~'")], severity="low",
                 title="sudoers drop-in is silently ignored",
                 why="sudo skips files whose names contain a dot or end with ~, so any rule inside has no effect.",
                 fix="Rename the file (e.g. 90-admin) if it is meant to apply.")
