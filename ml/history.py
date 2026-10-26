"""SQLite scan history. One row per scan; features and comparison maps stored as JSON."""
from __future__ import annotations
import datetime as dt
import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  scan_timestamp TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  meta TEXT NOT NULL,
  features TEXT NOT NULL,
  maps TEXT NOT NULL,
  UNIQUE(host, scan_timestamp)
);
"""


class History:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def ingest(self, snap: dict) -> tuple[int, bool]:
        """(id, created). Re-ingesting the same scan is a no-op."""
        meta = {k: snap[k] for k in ("collector_versions", "ran_as_root", "scan_spread_minutes", "map_root", "collectors_missing")}
        try:
            cur = self.db.execute(
                "INSERT INTO snapshots(host, scan_timestamp, ingested_at, meta, features, maps) VALUES (?,?,?,?,?,?)",
                (snap["host"], snap["scan_timestamp"], dt.datetime.now(dt.timezone.utc).isoformat(),
                 json.dumps(meta), json.dumps(snap["features"]), json.dumps(snap["maps"])))
            self.db.commit()
            return cur.lastrowid, True
        except sqlite3.IntegrityError:
            row = self.db.execute("SELECT id FROM snapshots WHERE host=? AND scan_timestamp=?",
                                  (snap["host"], snap["scan_timestamp"])).fetchone()
            return row[0], False

    def snapshots(self, host: str | None = None, limit: int | None = None) -> list[dict]:
        """Oldest -> newest. `limit` keeps the most recent N."""
        q = "SELECT id, host, scan_timestamp, ingested_at, meta, features, maps FROM snapshots"
        args: tuple = ()
        if host:
            q += " WHERE host=?"
            args = (host,)
        q += " ORDER BY scan_timestamp ASC"
        rows = self.db.execute(q, args).fetchall()
        if limit:
            rows = rows[-limit:]
        return [{"id": r[0], "host": r[1], "scan_timestamp": r[2], "ingested_at": r[3],
                 **json.loads(r[4]), "features": json.loads(r[5]), "maps": json.loads(r[6])} for r in rows]

    def hosts(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT host FROM snapshots")]

    def latest_host(self) -> str | None:
        row = self.db.execute("SELECT host FROM snapshots ORDER BY ingested_at DESC LIMIT 1").fetchone()
        return row[0] if row else None
