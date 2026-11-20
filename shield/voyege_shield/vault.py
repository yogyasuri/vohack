"""Pass vault (PDF §4A plane 5): agents get opaque session handles, never credentials.

The gate asks the vault to inject auth for a handle at forwarding time. Secrets are never returned to
callers and never written to the flight recorder. In production this is HashiCorp Vault; here it is an
in-memory store loaded from environment variables or a provided file.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field


@dataclass
class _Entry:
    agency: str
    role: str
    token: str = field(repr=False)
    expires_at: float = 0.0


class PassVault:
    def __init__(self, ttl_seconds: int = 900):
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        self.ttl = ttl_seconds

    def register(self, agency: str, role: str, token: str) -> str:
        """Store a provided test account's token and return a handle such as `A.agent#3f1c`."""
        handle = f"{agency}.{role}#{secrets.token_hex(2)}"
        with self._lock:
            self._entries[handle] = _Entry(agency, role, token, time.time() + self.ttl)
        return handle

    def describe(self, handle: str) -> dict:
        e = self._entries.get(handle)
        if not e:
            raise KeyError("unknown handle")
        return {"handle": handle, "agency": e.agency, "role": e.role, "expired": time.time() > e.expires_at}

    def auth_headers(self, handle: str) -> dict[str, str]:
        """Only the gate calls this. Expired handles fail closed."""
        e = self._entries.get(handle)
        if not e:
            raise PermissionError("unknown session handle")
        if time.time() > e.expires_at:
            raise PermissionError("session handle expired; refresh required")
        return {"Authorization": f"Bearer {e.token}"}

    def handles(self) -> list[dict]:
        return [self.describe(h) for h in self._entries]
