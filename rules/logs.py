import datetime as dt
from engine.core import rule, ev, Unknown


@rule(id="LOG-001", title="Authentication evidence is not retained", category="hygiene", severity="medium",
      confidence="high",
      why="With volatile journald storage (or very little history), logs of an intrusion vanish at reboot and cannot be investigated.",
      fix="Set Storage=persistent in /etc/systemd/journald.conf.d/ and create /var/log/journal; keep at least a week of history.",
      requires={"logs": ["infrastructure"]})
def log_001(ctx):
    infra = ctx.d("logs")["infrastructure"]
    if not infra.get("journalctl_present"):
        raise Unknown("journalctl not available: cannot assess log retention")
    storage = str((infra.get("journald_config") or {}).get("Storage", "auto")).lower()
    has_dir = infra.get("persistent_journal_dir_exists")
    if storage in ("volatile", "none") or (storage == "auto" and has_dir is False):
        ctx.fail("journal-persistence", [ev("logs", "infrastructure", f"Storage={storage}, /var/log/journal exists: {has_dir}", "Storage=persistent")])
    oldest = (infra.get("journal_span") or {}).get("oldest_epoch")
    if oldest is None:
        ctx.partial("journal history length unknown")
        return
    ts = dt.datetime.fromisoformat(ctx.env("logs")["timestamp"]).timestamp()
    days = (ts - oldest) / 86400
    if days < ctx.th("min_journal_days"):
        ctx.fail("journal-retention", [ev("logs", "infrastructure.journal_span.oldest_epoch", f"{days:.1f} days of history", f">= {ctx.th('min_journal_days')} days")])


@rule(id="LOG-002", title="Suspicious SSH login pattern", category="ioc", severity="high", confidence="medium",
      why="A successful login from an address that was also repeatedly failing is consistent with a successful password guess; a root login from a public address is high-risk in itself.",
      fix="Check whether you made these logins (who, when). If not, rotate that account's credentials and keys, review 'last' and the sudo log, and block the source.",
      requires={"logs": ["events"]})
def log_002(ctx):
    ssh = ctx.d("logs")["events"].get("ssh") or {}
    fails = {s["value"]: s["count"] for s in ssh.get("top_failed_sources", [])}
    min_f = ctx.th("brute_force_min_failures")
    for a in ssh.get("accepted", []):
        why = []
        if fails.get(a["source"], 0) >= min_f:
            why.append(f"{fails[a['source']]} failed attempts from the same source")
        if a["user"] == "root" and a.get("scope") == "public":
            why.append("root login from a public address")
        if why:
            ctx.fail(f"{a['user']}@{a['source']}", [ev("logs", "events.ssh.accepted", f"{a['method']} login, {a['count']}x; " + "; ".join(why),
                                                       "no success after failures; no root from public IPs")],
                     exposed=True, runs_as_root=a["user"] == "root")
    ctx.note("only the top 20 failing sources are considered")
