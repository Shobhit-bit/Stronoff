import rules  # noqa: F401  (registers rules)
from engine.config import load_thresholds
from engine.core import REGISTRY
from engine.loader import COLLECTORS, Loaded
from engine.runner import evaluate

TS = "2026-10-21T10:00:00+00:00"


def env(name, data, root=True, version="1.2", warnings=None):
    return {"schema_version": "1.0", "collector_version": version, "collector": name, "timestamp": TS,
            "host": "t", "ran_as_root": root, "errors": [], "warnings": warnings or [], "data": data}


def run(rule_id, roots=None, **collectors):
    """Evaluate one rule against in-memory collector data. Missing collectors count as 'missing'."""
    roots = roots or {}
    loaded = {n: Loaded.from_envelope(n, env(n, d, roots.get(n, True))) for n, d in collectors.items()}
    for n in COLLECTORS:
        loaded.setdefault(n, Loaded(n, "missing", f"{n}.json not found"))
    return evaluate(REGISTRY[rule_id], loaded, load_thresholds(), TS)


def meta(path, mode="0644", owner="root", group="root", **kw):
    m = {"path": path, "exists": True, "mode": mode, "owner": owner, "group": group, "uid": 0, "gid": 0,
         "is_symlink": False, "is_dir": False, "world_readable": mode[-1] in "4567",
         "world_writable": mode[-1] in "2367", "group_writable": mode[-2] in "2367"}
    m.update(kw)
    return m


def subjects(res):
    return sorted(f.subject for f in res.findings)


def sev(res):
    return {f.subject: f.severity for f in res.findings}


def proc(pid=100, name="x", exe="/usr/bin/x", user="root", **kw):
    p = {"pid": pid, "ppid": 1, "name": name, "kernel_thread": False, "user": user, "exe": exe,
         "exe_readable": True, "exe_deleted": False, "exe_memfd": False, "exe_under_tmp": False,
         "cmdline": exe, "package": "pkg"}
    p.update(kw)
    return p
