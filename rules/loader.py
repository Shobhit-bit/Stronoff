"""Load collector JSON and decide whether each one is usable (C2: unreadable input is UNKNOWN)."""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path

from . import MIN_COLLECTOR_VERSION

COLLECTORS = ["accounts", "filesystem", "processes", "services", "packages",
              "configs", "network", "logs", "kernel", "persistence"]


def _ver(v) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


@dataclass
class Loaded:
    name: str
    status: str                    # ok | missing | load_error | stale | not_a_collector
    reason: str = ""
    env: dict | None = None

    @property
    def usable(self) -> bool:
        return self.status == "ok"

    @property
    def data(self) -> dict:
        return (self.env or {}).get("data") or {}

    @property
    def ran_as_root(self) -> bool:
        return bool((self.env or {}).get("ran_as_root"))

    @property
    def first_warning(self) -> str:
        w = (self.env or {}).get("warnings") or []
        return w[0] if w else ""

    @classmethod
    def from_envelope(cls, name: str, env: dict) -> "Loaded":
        v = env.get("collector_version")
        if v is None or _ver(v) < _ver(MIN_COLLECTOR_VERSION):
            return cls(name, "stale",
                       f"{name}.json was produced by collector v{v or 'pre-1.1'}; v{MIN_COLLECTOR_VERSION}+ "
                       "required (older versions had fixed bugs). Re-run the collectors.", env)
        if env.get("collector") != name:
            return cls(name, "not_a_collector", f"{name}.json has collector={env.get('collector')!r}", env)
        return cls(name, "ok", "", env)


def load_all(out_dir: str | Path) -> dict[str, Loaded]:
    out_dir = Path(out_dir)
    loaded = {}
    for name in COLLECTORS:
        p = out_dir / f"{name}.json"
        if not p.exists():
            loaded[name] = Loaded(name, "missing", f"{name}.json not found in {out_dir}")
            continue
        try:
            env = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            loaded[name] = Loaded(name, "load_error", f"{name}.json unreadable: {e}")
            continue
        loaded[name] = Loaded.from_envelope(name, env)
    return loaded
