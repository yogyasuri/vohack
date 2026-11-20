"""Flight recorder (PDF Part B §4A plane 5; Part A §14).

Append-only, hash-chained log. Every record carries the hash of the previous one, so any edit or deletion
breaks the chain and `verify()` reports where. The gate writes the record *before* forwarding a request and
refuses to forward when the write fails ("no log write = no forwarding").
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


class RecorderError(RuntimeError):
    pass


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class FlightRecorder:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.available = True  # safety drills flip this to simulate a log outage
        self._last = GENESIS
        self._count = 0
        if self.path.exists():
            for rec in self.records():
                self._last = rec["hash"]
                self._count += 1

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            if not self.available:
                raise RecorderError("flight recorder unavailable")
            body = {"seq": self._count, "ts": round(time.time(), 3), "kind": kind, "data": data, "prev": self._last}
            rec = {**body, "hash": _digest(self._last, body)}
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, sort_keys=True) + "\n")
                    fh.flush()
            except OSError as exc:  # disk full, permissions, ...
                raise RecorderError(str(exc)) from exc
            self._last, self._count = rec["hash"], self._count + 1
            return rec

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> dict:
        prev = GENESIS
        recs = self.records()
        for i, rec in enumerate(recs):
            body = {k: rec[k] for k in ("seq", "ts", "kind", "data", "prev")}
            if rec["prev"] != prev or _digest(prev, body) != rec["hash"]:
                return {"ok": False, "records": len(recs), "broken_at": i}
            prev = rec["hash"]
        return {"ok": True, "records": len(recs), "head": prev}

    def __len__(self) -> int:
        return self._count
