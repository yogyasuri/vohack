"""Safety gate (PDF Part B §7: seven checks on every request; Part A §14 rules of engagement).

The gate is the only network path from Voyege workers to the approved target. For every request it:
  1. checks the host and path against the approved area (block is the default),
  2. applies the speed limit (global + per-host budgets) and health-based back-off,
  3. allows synthetic data only (request bodies must carry the synthetic tag when they create objects),
  4. requires a registered undo plan for state-changing (L2/L3) requests,
  5. requires approval for L3 (standing approval within budget; per-batch for concurrency),
  6. writes the flight-recorder entry *before* forwarding, refusing if it cannot,
  7. honours the kill switch (all traffic dropped immediately).
Responses are capped in size and only field names and IDs are kept as evidence.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from .recorder import FlightRecorder, RecorderError
from .vault import PassVault

SYNTHETIC_TAG = "VOYEGE-SYNTH"


class GateBlocked(Exception):
    def __init__(self, check: str, reason: str):
        super().__init__(f"[{check}] {reason}")
        self.check, self.reason = check, reason


@dataclass
class GateRequest:
    method: str
    url: str
    handle: str | None = None
    tier: str = "L0"
    test_id: str = "manual"
    json_body: dict | None = None
    cleanup_registered: bool = False
    approval_id: str | None = None
    concurrency: bool = False
    include_headers: bool = False   # read-only: return response header names/values (for posture checks)
    return_text: bool = False       # read-only: return capped response text (e.g. a public JS bundle)


@dataclass
class _Health:
    baseline_ms: float | None = None
    latencies: deque = field(default_factory=lambda: deque(maxlen=50))
    statuses: deque = field(default_factory=lambda: deque(maxlen=50))
    degraded_since: float | None = None


class SafetyGate:
    def __init__(self, policy: dict, recorder: FlightRecorder, vault: PassVault,
                 transport: httpx.BaseTransport | None = None, approvals=None):
        self.policy = policy
        self.recorder = recorder
        self.vault = vault
        self.approvals = approvals  # callable(approval_id) -> bool
        self.client = httpx.Client(transport=transport, timeout=10.0, follow_redirects=False)
        self._lock = threading.Lock()
        self.killed = False
        self.paused_reason: str | None = None
        self.rate_factor = 1.0
        self._sent: deque = deque()            # timestamps of forwarded requests (global)
        self._sent_host: dict[str, deque] = {}
        self._health: dict[str, _Health] = {}
        self._blocks: deque = deque()          # out-of-scope blocks in the last hour
        self.counters = {"forwarded": 0, "blocked": 0, "out_of_scope": 0, "budget_waits": 0,
                         "backoffs": 0, "log_refusals": 0, "kill_drops": 0}
        self.on_alarm = None                   # orchestrator hook

    # ---- controls -------------------------------------------------------------------------------
    def kill(self, who: str = "operator") -> None:
        self.killed = True
        self._safe_log("kill_switch", {"by": who, "state": "engaged"})
        self._alarm("kill switch engaged")

    def release(self, who: str = "operator") -> None:
        self.killed, self.paused_reason, self.rate_factor = False, None, 1.0
        self._safe_log("kill_switch", {"by": who, "state": "released"})

    def status(self) -> dict:
        return {"killed": self.killed, "paused": self.paused_reason, "rate_factor": self.rate_factor,
                "counters": dict(self.counters), "recorder": len(self.recorder),
                "recorder_available": self.recorder.available}

    # ---- the seven checks -----------------------------------------------------------------------
    def _check(self, req: GateRequest) -> tuple[str, str]:
        if self.killed:
            self.counters["kill_drops"] += 1
            raise GateBlocked("7-kill", "kill switch engaged")
        if self.paused_reason:
            raise GateBlocked("2-health", f"paused: {self.paused_reason}")
        parts = urlsplit(req.url)
        host, path = (parts.hostname or "").lower(), parts.path or "/"
        scope = self.policy["scope"]
        if parts.scheme not in ("http", "https") or host not in scope["allowed_hosts"]:
            self._out_of_scope(req, host)
            raise GateBlocked("1-scope", f"host '{host}' is not on the approved list")
        if any(path.startswith(p) for p in scope["denied_path_prefixes"]):
            self._out_of_scope(req, host)
            raise GateBlocked("1-scope", f"path '{path}' is denied")
        tier = self.policy["tiers"].get(req.tier)
        if not tier:
            raise GateBlocked("5-tier", f"unknown tier {req.tier}")
        if req.method.upper() not in tier["methods"]:
            raise GateBlocked("5-tier", f"{req.method} not allowed at {req.tier}")
        if req.method.upper() in ("POST", "PUT", "PATCH") and req.json_body is not None:
            if SYNTHETIC_TAG not in json.dumps(req.json_body):
                raise GateBlocked("3-synthetic", "state-changing body lacks the synthetic tag")
        if tier.get("requires_cleanup") and req.method.upper() not in ("GET", "HEAD") and not req.cleanup_registered:
            raise GateBlocked("4-undo", "no undo plan registered before a state-changing request")
        if req.tier == "L3":
            needs = req.concurrency or tier.get("approval") != "standing_within_budget"
            if needs and not (req.approval_id and self.approvals and self.approvals(req.approval_id)):
                raise GateBlocked("5-approval", "L3 batch requires a valid human approval")
        return host, path

    def _out_of_scope(self, req: GateRequest, host: str) -> None:
        self.counters["out_of_scope"] += 1
        now = time.time()
        self._blocks.append(now)
        while self._blocks and now - self._blocks[0] > 3600:
            self._blocks.popleft()
        if len(self._blocks) >= self.policy["backoff"]["out_of_scope_blocks_per_hour_to_pause"]:
            self.paused_reason = "repeated out-of-scope attempts; planner paused"
            self._alarm(self.paused_reason)

    def _budget(self, host: str) -> None:
        b = self.policy["budgets"]
        g_rps = max(1, b["global_rps"] * self.rate_factor)
        h_rps = max(1, b["per_host_rps"] * self.rate_factor)
        while True:
            with self._lock:
                now = time.time()
                for q in (self._sent, self._sent_host.setdefault(host, deque())):
                    while q and now - q[0] > 1.0:
                        q.popleft()
                if len(self._sent) < g_rps and len(self._sent_host[host]) < h_rps:
                    self._sent.append(now)
                    self._sent_host[host].append(now)
                    return
            self.counters["budget_waits"] += 1
            time.sleep(0.05)

    def _observe(self, host: str, ms: float, status: int) -> None:
        h = self._health.setdefault(host, _Health())
        h.latencies.append(ms)
        h.statuses.append(status)
        if h.baseline_ms is None and len(h.latencies) >= 5:
            h.baseline_ms = sorted(h.latencies)[len(h.latencies) // 2]
        bo = self.policy["backoff"]
        p95 = sorted(h.latencies)[int(len(h.latencies) * 0.95) - 1] if len(h.latencies) >= 5 else 0
        err = sum(1 for s in h.statuses if s >= 500) / len(h.statuses)
        strained = (h.baseline_ms and p95 > max(bo["latency_multiplier"] * h.baseline_ms, h.baseline_ms + 25)) or (len(h.statuses) >= 5 and err > bo["error_rate"])
        if status == 429 or strained:
            self.rate_factor = max(0.1, self.rate_factor / 2)
            self.counters["backoffs"] += 1
            h.degraded_since = h.degraded_since or time.time()
            if time.time() - h.degraded_since >= bo["pause_after_seconds"]:
                self.paused_reason = f"target {host} strained for {bo['pause_after_seconds']}s"
                self._alarm(self.paused_reason)
        else:
            h.degraded_since = None

    # ---- forwarding -----------------------------------------------------------------------------
    def request(self, req: GateRequest) -> dict:
        try:
            host, path = self._check(req)
        except GateBlocked as blk:
            self.counters["blocked"] += 1
            self._safe_log("blocked", {"test_id": req.test_id, "method": req.method, "url": req.url,
                                       "tier": req.tier, "check": blk.check, "reason": blk.reason})
            raise
        self._budget(host)
        headers = {"X-Voyege-Test": req.test_id}
        if req.handle:
            headers.update(self.vault.auth_headers(req.handle))
        entry = {"test_id": req.test_id, "method": req.method, "url": req.url, "tier": req.tier,
                 "handle": req.handle, "body_fields": sorted((req.json_body or {}).keys())}
        try:
            self.recorder.append("request", entry)  # written before forwarding
        except RecorderError as exc:
            self.counters["log_refusals"] += 1
            self._alarm(f"flight recorder unavailable: {exc}")
            raise GateBlocked("6-recorder", "cannot record request; refusing to forward") from exc
        t0 = time.time()
        resp = self.client.request(req.method, req.url, headers=headers, json=req.json_body)
        ms = (time.time() - t0) * 1000
        self._observe(host, ms, resp.status_code)
        self.counters["forwarded"] += 1
        evidence = self._minimise(resp)
        self._safe_log("response", {"test_id": req.test_id, "status": resp.status_code, "ms": round(ms, 1),
                                    "fields": evidence["fields"], "ids": evidence["ids"]})
        out = {"status": resp.status_code, "ms": ms, "url": str(resp.url), **evidence}
        if req.include_headers:
            # Header metadata for posture checks. Set-Cookie values are redacted to attributes only,
            # so a session token is never kept (minimum-evidence rule).
            out["headers"] = {k: v for k, v in resp.headers.multi_items() if k.lower() != "set-cookie"}
            out["cookies"] = [self._cookie_attrs(v) for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
        if req.return_text:
            out["text"] = resp.content[: self.policy["budgets"]["max_response_bytes"]].decode("utf-8", "replace")
        return out

    @staticmethod
    def _cookie_attrs(set_cookie: str) -> dict:
        parts = [p.strip() for p in set_cookie.split(";")]
        name = parts[0].split("=", 1)[0] if parts else ""
        flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
        samesite = next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None)
        return {"name": name, "secure": "secure" in flags, "httponly": "httponly" in flags, "samesite": samesite}

    def _minimise(self, resp: httpx.Response) -> dict:
        b = self.policy["budgets"]
        raw = resp.content[: b["max_response_bytes"]]
        fields, ids = [], []
        try:
            data = json.loads(raw)
        except ValueError:
            return {"fields": [], "ids": [], "truncated": len(resp.content) > len(raw)}
        items = data if isinstance(data, list) else data.get("items", [data]) if isinstance(data, dict) else []
        for item in items[: b["max_records_per_list"]]:
            if isinstance(item, dict):
                fields = sorted(set(fields) | set(item.keys()))
                if "id" in item:
                    ids.append(item["id"])
        return {"fields": fields, "ids": ids, "truncated": len(resp.content) > len(raw)}

    def _safe_log(self, kind: str, data: dict) -> None:
        try:
            self.recorder.append(kind, data)
        except RecorderError:
            self.counters["log_refusals"] += 1

    def _alarm(self, msg: str) -> None:
        if self.on_alarm:
            self.on_alarm(msg)
