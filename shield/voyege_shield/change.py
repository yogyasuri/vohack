"""Change detector (PDF Part B §4A plane 2; §4F N1 "see every change").

Four independent signals plus a DNS/certificate watcher:
  * deploy webhook  - HMAC-signed; duplicates for the same service merged within 2 minutes
  * bundle diff     - hash the front-end bundle; parse routes only when the hash changed
  * shape drift     - new response field / status / auth change per template (catches config-only changes)
  * log diff        - new templates in gateway logs (shadow candidates)
  * DNS / CT        - new host on the approved list -> discovery; otherwise report only, never contacted
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field

from .inventory import _JS_ROUTE, template


@dataclass
class ChangeEvent:
    kind: str
    service: str
    routes: list = field(default_factory=list)
    detail: str = ""
    ts: float = field(default_factory=time.time)
    release: str | None = None


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class ChangeDetector:
    def __init__(self, policy: dict, secret: str, allowed_hosts: list[str]):
        self.secret = secret
        self.dedupe = policy["webhook"]["dedupe_seconds"]
        self.allowed_hosts = set(allowed_hosts)
        self._seen_webhooks: dict[str, float] = {}
        self._bundle_hash: str | None = None
        self._bundle_routes: set[str] = set()
        self._shapes: dict[str, set] = {}
        self._log_templates: set[str] = set()
        self._hosts: set[str] = set()
        self.forgotten_hosts: list[dict] = []

    def webhook(self, body: bytes, signature: str, payload: dict) -> ChangeEvent | None:
        if not hmac.compare_digest(sign(self.secret, body), signature or ""):
            raise PermissionError("bad webhook signature")
        svc, now = payload.get("service", "unknown"), time.time()
        if now - self._seen_webhooks.get(svc, 0) < self.dedupe and not payload.get("force"):
            return None
        self._seen_webhooks[svc] = now
        return ChangeEvent("deploy", svc, [template(r) for r in payload.get("routes", [])],
                           payload.get("notes", ""), release=payload.get("release"))

    def bundle(self, js: str) -> ChangeEvent | None:
        h = hashlib.sha256(js.encode()).hexdigest()
        if h == self._bundle_hash:
            return None
        routes = {template(m.group(1)) for m in _JS_ROUTE.finditer(js)}
        first = self._bundle_hash is None
        added, removed = routes - self._bundle_routes, self._bundle_routes - routes
        self._bundle_hash, self._bundle_routes = h, routes
        if first:
            return None
        return ChangeEvent("bundle", "frontend", sorted(added | removed),
                           f"+{len(added)} / -{len(removed)} routes in bundle {h[:8]}")

    def shape(self, endpoint_key: str, fields: list[str], status: int) -> ChangeEvent | None:
        sig = set(fields) | {f"status:{status // 100}xx"}
        prev = self._shapes.get(endpoint_key)
        self._shapes[endpoint_key] = sig
        if prev is None or sig == prev:
            return None
        return ChangeEvent("shape", endpoint_key.split(" ")[-1].split("/")[3] if "/api/" in endpoint_key else "unknown",
                           [endpoint_key.split(" ", 1)[1]], f"fields +{sorted(sig - prev)} -{sorted(prev - sig)}")

    def logs(self, rows: list[dict]) -> ChangeEvent | None:
        tpls = {template(r["path"]) for r in rows}
        first = not self._log_templates
        new = tpls - self._log_templates
        self._log_templates |= tpls
        if first or not new:
            return None
        return ChangeEvent("traffic", "gateway", sorted(new), f"{len(new)} new templates in gateway logs")

    def dns(self, hosts: list[str]) -> list[ChangeEvent]:
        out, first = [], not self._hosts
        for h in hosts:
            if h in self._hosts:
                continue
            self._hosts.add(h)
            if first:
                continue
            if h in self.allowed_hosts:
                out.append(ChangeEvent("dns", "platform", [], f"new approved host {h}: discovery pass queued"))
            else:
                self.forgotten_hosts.append({"host": h, "seen": time.time(), "action": "reported, never contacted"})
                out.append(ChangeEvent("dns-report", "platform", [], f"possible forgotten asset {h} (out of scope)"))
        return out
