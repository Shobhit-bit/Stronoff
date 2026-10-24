import re
from engine.core import rule, ev, Unknown
from ._helpers import under

_TOK = re.compile(r"^(Package|Database)?(Never|Optional|Required)$")


def sig_levels(s: str):
    pkg = db = None
    for t in str(s).split():
        m = _TOK.match(t)
        if not m:
            continue
        scope, lvl = m.groups()
        if scope in (None, "Package"):
            pkg = lvl
        if scope in (None, "Database"):
            db = lvl
    return pkg, db


@rule(id="PKG-001", title="Package signature verification weakened", category="weakness", severity="high",
      confidence="high", applies_to="arch",
      why="pacman's signature checks are what stops a tampered mirror or network attacker from installing malicious packages. 'Never' disables them; 'Optional' accepts unsigned packages.",
      fix="Set SigLevel = Required DatabaseOptional in /etc/pacman.conf (the Arch default) unless a local file repository needs an exception, then re-check.",
      requires={"packages": ["pacman_conf"]})
def pkg_001(ctx):
    conf = ctx.d("packages")["pacman_conf"]
    scopes = [(f"global SigLevel", s) for s in (conf.get("options") or {}).get("SigLevel", [])]
    scopes += [(f"repo [{r['name']}]", r["sig_level"]) for r in conf.get("repos") or [] if r.get("sig_level")]
    for label, s in scopes:
        pkg, db = sig_levels(s)
        if "Never" in (pkg, db):
            ctx.fail(label, [ev("packages", "pacman_conf", f"SigLevel = {s}", "Required")], severity="high")
        elif pkg == "Optional":
            ctx.fail(label, [ev("packages", "pacman_conf", f"SigLevel = {s}", "Required")], severity="medium",
                     why="Unsigned packages are accepted from this scope, so a tampered package would install without warning.")


@rule(id="PKG-002", title="System not fully upgraded recently", category="hygiene", severity="medium",
      confidence="high", applies_to="arch",
      why="Arch is a rolling release: security fixes only arrive with full upgrades. The longer since the last one, the more known vulnerabilities are present.",
      fix="Run a full upgrade (pacman -Syu) after reading the Arch news; never run pacman -Sy alone.",
      requires={"packages": ["updates"]})
def pkg_002(ctx):
    days = ctx.get("packages", "updates.last_full_upgrade.days_ago")
    if days is None:
        raise Unknown("last full upgrade date not found (pacman.log unreadable or no full upgrade logged)")
    th = ctx.th("stale_upgrade_days")
    sev = "high" if days > th["high"] else "medium" if days > th["medium"] else None
    if sev:
        pending = ctx.get("packages", "updates.pending")
        ctx.fail("system", [ev("packages", "updates.last_full_upgrade.days_ago", days,
                               f"<= {th['medium']} days"),
                            ev("packages", "updates.pending", f"{len(pending)} pending" if pending is not None else "unknown", "0")],
                 severity=sev)


@rule(id="PKG-003", title="Installed file differs from its package", category="ioc", severity="high",
      confidence="medium", applies_to="arch",
      why="A package file whose size or checksum changed was modified after installation. For authentication binaries this is a classic way to plant a backdoor.",
      fix="Reinstall the package (pacman -S <package>) after saving the modified file for inspection; compare with a trusted copy. Review how the file changed.",
      requires={"packages": ["integrity"]})
def pkg_003(ctx):
    integ = ctx.d("packages")["integrity"]
    if not integ.get("performed"):
        raise Unknown("integrity check not performed (needs root; skipped in fast mode)")
    if integ.get("truncated"):
        ctx.note("integrity lists were capped; see packages.integrity.totals")
    auth, prefixes = set(ctx.th("auth_binaries")), tuple(ctx.th("auth_prefixes"))
    for f in integ.get("altered_files", []):
        if not f.get("content_changed"):
            continue
        p = f["path"]
        crit = p in auth or p.startswith(prefixes)
        ctx.fail(p, [ev("packages", "integrity.altered_files", f"{f.get('package')}: {', '.join(f.get('reasons', []))}", "matches package")],
                 severity="critical" if crit else "high", runs_as_root=crit)
