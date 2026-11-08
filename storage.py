"""Tiny JSON-file store (keys hashed; scans keyed by id)."""
import hashlib
import json
import threading
from pathlib import Path


class Store:
    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "acase_db.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = {"keys": {}, "scans": {}}
        if self.path.exists():
            try:
                self.db = json.loads(self.path.read_text())
            except json.JSONDecodeError:
                pass

    def _flush(self):
        self.path.write_text(json.dumps(self.db, indent=2))

    @staticmethod
    def _h(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    def add_key(self, key: str, email: str, host: str):
        with self.lock:
            self.db["keys"][self._h(key)] = {"email": email, "host": host}
            self._flush()

    def key_info(self, key: str):
        return self.db["keys"].get(self._h(key or ""))

    def save_scan(self, scan: dict):
        with self.lock:
            self.db["scans"][scan["id"]] = scan
            self._flush()

    def get_scan(self, sid: str):
        return self.db["scans"].get(sid)

    def list_scans(self, email: str):
        rows = [s for s in self.db["scans"].values() if s.get("owner") == email]
        return sorted(rows, key=lambda s: s["created_at"], reverse=True)
