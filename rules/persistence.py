from engine.core import rule, ev
from ._helpers import iter_persistence, under


@rule(id="PER-001", title="Suspicious command pattern at a persistence point", category="ioc", severity="high",
      confidence="medium",
      why="Cron jobs, systemd units, shell startup files, autostart entries and hooks run automatically. Download-and-execute, reverse-shell or encoded-payload patterns there are consistent with malware persistence.",
      fix="Open the file and read what it does. Installers such as rustup/nvm legitimately pipe curl to sh from a .bashrc: if you recognise it, allowlist by path and sha256; if not, remove it and investigate.",
      requires={"persistence": ["users_scanned"]})
def per_001(ctx):
    d, strong = ctx.d("persistence"), set(ctx.th("strong_pattern_hits"))
    for sec in ("cron", "systemd", "shell", "misc"):
        if d.get(sec) is None:
            ctx.partial(f"persistence section '{sec}' failed to collect")
    for section, r in iter_persistence(d):
        if section == "ssh_authorized_keys":
            continue
        hits = set(r.get("pattern_hits") or [])
        path = r.get("path")
        exec_bad = [p for p in r.get("exec_paths") or [] if under(p, ctx.th("user_writable_prefixes"))]
        e = ev("persistence", section, f"{path}: hits {sorted(hits)} exec_paths {r.get('exec_paths') or []}",
               "no download-and-execute / reverse-shell patterns; no execution from user-writable paths")
        if hits & strong:
            ctx.fail(path, [e])
        elif exec_bad:
            ctx.fail(path, [e], why="This unit starts a program from a user-writable location, which anyone with that access can replace.")
        elif "runs_from_tmp" in hits:
            ctx.fail(path, [e], severity="medium", confidence="low",
                     why="The file references paths under /tmp-like directories; often harmless (TMPDIR settings) but worth a look.")


@rule(id="PER-002", title="Preload or persistence file can be tampered with", category="weakness", severity="high",
      confidence="high",
      why="/etc/ld.so.preload injects a library into every program and is rare outside rootkits. Writable startup, cron, unit or SSH key files let non-root users plant code that runs later with someone else's privileges.",
      fix="For ld.so.preload: identify the library and who added it. For writable files: restore the mode (e.g. chmod go-w) after reviewing the contents, and check sshd StrictModes.",
      requires={"persistence": ["misc", "users_scanned"]})
def per_002(ctx):
    d = ctx.d("persistence")
    pre = (d["misc"] or {}).get("ld_so_preload") or {}
    if pre.get("entries"):
        ctx.fail("/etc/ld.so.preload", [ev("persistence", "misc.ld_so_preload.entries", pre["entries"], "file absent or empty")],
                 severity="high", confidence="medium", runs_as_root=True)
    for section, r in iter_persistence(d):
        if section == "ssh_authorized_keys":
            for m in (r, r.get("ssh_dir_meta") or {}):
                if m.get("world_writable") or m.get("group_writable"):
                    ctx.fail(m.get("path"), [ev("persistence", section, f"mode {m.get('mode')} {m.get('owner')}:{m.get('group')}", "not group/world-writable")])
            continue
        group_bad = r.get("group_writable") and r.get("group") not in (None, "root", r.get("owner"))
        if r.get("world_writable") or group_bad:
            ctx.fail(r.get("path"), [ev("persistence", section, f"mode {r.get('mode')} {r.get('owner')}:{r.get('group')}", "not writable by others")])
