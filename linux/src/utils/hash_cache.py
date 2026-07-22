"""Cache de hashes SHA256 con SQLite — evita re-escanear archivos identicos."""
import json
import time
import sqlite3
from pathlib import Path


class HashCache:
    def __init__(self, db_path=None):
        if db_path is None:
            import os
            db_dir = Path(os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME")
                           or (Path.home() / ".config")) / "cPacleanS"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "scan_cache.db")
        self.db_path = str(db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS file_cache ("
                "sha256 TEXT PRIMARY KEY, "
                "scan_result TEXT, "
                "vt_result TEXT, "
                "timestamp INTEGER)"
            )

    def get(self, sha256, max_age_days=30):
        cutoff = int(time.time()) - (max_age_days * 86400)
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT scan_result, vt_result FROM file_cache "
                    "WHERE sha256 = ? AND timestamp > ?",
                    (sha256, cutoff),
                ).fetchone()
            if row:
                return {
                    "scan_result": json.loads(row[0]) if row[0] else None,
                    "vt_result": json.loads(row[1]) if row[1] else None,
                }
        except sqlite3.Error:
            pass
        return None

    def put(self, sha256, scan_result=None, vt_result=None):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO file_cache "
                    "(sha256, scan_result, vt_result, timestamp) VALUES (?, ?, ?, ?)",
                    (
                        sha256,
                        json.dumps(scan_result) if scan_result is not None else None,
                        json.dumps(vt_result) if vt_result is not None else None,
                        int(time.time()),
                    ),
                )
        except sqlite3.Error:
            pass

    def stats(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                count = conn.execute("SELECT COUNT(*) FROM file_cache").fetchone()[0]
            size_mb = round(Path(self.db_path).stat().st_size / (1024 * 1024), 2)
        except (sqlite3.Error, OSError):
            count, size_mb = 0, 0
        return {"count": count, "size_mb": size_mb}

    def clear(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM file_cache")
        except sqlite3.Error:
            pass
        try:
            c = sqlite3.connect(self.db_path, isolation_level=None)
            c.execute("VACUUM")
            c.close()
        except sqlite3.Error:
            pass
