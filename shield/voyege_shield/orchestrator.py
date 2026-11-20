"""Orchestrator (PDF §13 component 13, Part B §4A plane 3) and the deterministic test planner.

Change events go onto an ordered queue (Redis Streams / Temporal in production, an in-process queue here).
Each run: refresh inputs -> update inventory -> plan (rules first; only routes that exist in the graph) ->
execute through the gate / rule engine -> verify -> triage -> tickets -> retest. Any safety alarm pauses the
pipeline. Heartbeats make silent failure visible (OPS-01).
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from pathlib import Path

import httpx
import yaml

from . import fraud, rules as R
from .change import ChangeDetector, ChangeEvent, sign
from .diagnose import LiveDiagnostic
from .feed import HOST, SyntheticFeed
from .gate import GateBlocked, GateRequest, SafetyGate
from .inventory import Inventory, template
from .recorder import FlightRecorder
from .triage import FindingDesk
from .vault import PassVault

ROOT = Path(__file__).resolve().parent.parent
RULE_ROUTES = {  # which changed routes make which rule relevant
    "INV-M1": ["/api/v2/bookings", "/api/v2/quotes"], "INV-M10": ["/api/v2/agency/markup"],
    "INV-M2": ["/api/v2/bookings/{bookingId}/refunds"], "INV-M7": ["/api/v2/bookings/{bookingId}/refunds"],
    "INV-M3": ["/api/v2/bookings/{bookingId}/refunds"], "INV-M4": ["/api/v2/bookings/{bookingId}/confirm", "/api/v2/bookings/{bookingId}/pay"],
    "INV-C1": ["/api/v2/coupons/redeem"], "INV-M8": ["/api/v2/quotes"], "INV-M5": ["/api/v2/wallet"],
    "INV-S2": ["/api/v2/holds"], "INV-R1": ["/api/v2/bookings"],
}


class StagingStub:
    """Benign stand-in for the approved staging host, used only to show gate behaviour (validation requests,
    latency back-off). It answers with field names and status codes; it holds no data and no flaws."""

    def __init__(self, inventory_fields: dict[str, list[str]]):
        self.fields = inventory_fields
        self.extra_latency = 0.0
        self.fail_rate = 0.0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.extra_latency:
            time.sleep(self.extra_latency)
        if self.fail_rate and (hash(request.url.path) % 100) < self.fail_rate * 100:
            return httpx.Response(503, json={"error": "unavailable"})
        tpl = template(request.url.path)
        auth = "authorization" in request.headers
        if tpl.startswith("/api/v1/"):
            return httpx.Response(200, json={"id": "BK1", **{f: "<synthetic>" for f in ("agency_id", "traveller_name", "passport", "amount")}})
        if not auth:
            return httpx.Response(401, json={"error": "login required"})
        return httpx.Response(200, json={"id": "X1", **{f: "<synthetic>" for f in self.fields.get(tpl, ["status"])}})


class Orchestrator:
    def __init__(self, data_dir: str | Path | None = None, seed: int = 7):
        self.data = Path(data_dir or ROOT / "data")
        self.data.mkdir(parents=True, exist_ok=True)
        cfg = ROOT / "config"
        self.policy = yaml.safe_load((cfg / "policy.yaml").read_text())
        self.catalogue = yaml.safe_load((cfg / "invariants.yaml").read_text())["rules"]
        self.owners = yaml.safe_load((cfg / "owners.yaml").read_text())
        self.secret = os.environ.get(self.policy["webhook"]["secret_env"], "voyege-demo-secret")
        self.recorder = FlightRecorder(self.data / f"flight-{int(time.time())}.jsonl")
        self.vault = PassVault()
        self.desk = FindingDesk(self.catalogue, self.data / "tickets", self.recorder)
        self.stub = StagingStub({"/api/v2/bookings/{bookingId}": ["agency_id", "traveller_name", "amount", "status"],
                                 "/api/v2/wallet": ["balance", "credit_limit"]})
        self.gate = SafetyGate(self.policy, self.recorder, self.vault, httpx.MockTransport(self.stub),
                               approvals=self.desk.approval_valid)
        self.gate.on_alarm = self._alarm
        self.feed = SyntheticFeed(seed=seed)
        self.diagnostic = LiveDiagnostic(self.policy, self.data / "diag", self.owners)
        self.inventory = Inventory(self.policy, self.owners)
        self.detector = ChangeDetector(self.policy, self.secret, self.policy["scope"]["allowed_hosts"])
        self.events: queue.Queue[ChangeEvent] = queue.Queue()
        self.timeline: list[dict] = []
        self.plans: list[dict] = []
        self.fraud_hits: dict = {}
        self.alarms: list[dict] = []
        self.heartbeat = time.time()
        self.paused = False
        self.runs = 0
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None
        # provided test accounts: two agencies × roles (tokens are synthetic)
        self.handles = {f"{a}.{r}": self.vault.register(a, r, f"tok-{a}-{r}-synthetic")
                        for a in ("A", "B") for r in ("admin", "agent", "subagent")}

    # ---- lifecycle ------------------------------------------------------------------------------
    def start(self) -> None:
        self.cold_start()
        self._worker = threading.Thread(target=self._loop, daemon=True, name="voyege-orchestrator")
        self._worker.start()

    def _loop(self) -> None:
        while True:
            try:
                ev = self.events.get(timeout=2)
            except queue.Empty:
                self.heartbeat = time.time()
                continue
            if self.paused or self.gate.killed:
                self._t("paused", f"event {ev.kind} held: pipeline paused")
                self.events.put(ev)
                time.sleep(2)
                continue
            try:
                self.handle(ev)
            except Exception as exc:  # never die silently
                self._alarm(f"pipeline error: {exc}")
            self.heartbeat = time.time()

    def _t(self, kind: str, msg: str, **extra) -> None:
        with self._lock:
            self.timeline.append({"ts": time.time(), "kind": kind, "msg": msg, **extra})
            self.timeline = self.timeline[-200:]

    def _alarm(self, msg: str) -> None:
        self.alarms.append({"ts": time.time(), "msg": msg})
        self.paused = self.paused or "kill" in msg or "recorder" in msg or "paused" in msg
        self._t("alarm", msg)

    # ---- cold start: discovery + full sweep -------------------------------------------------------
    def cold_start(self) -> None:
        self._t("start", "cold start: discovery from HAR, JS bundle, gateway logs, DNS")
        for role in ("agent", "admin", "subagent"):
            for agency in ("A", "B"):
                self.inventory.add_har(self.feed.har(agency, role), role)
        self.inventory.add_js_bundle(self.feed.js_bundle())
        self.detector.bundle(self.feed.js_bundle())
        self.inventory.add_gateway_logs(self.feed.logs)
        self.detector.logs(self.feed.logs)
        self.detector.dns(self.feed.dns())
        self.validate()
        self.inventory.classify()
        self._t("inventory", f"{len(self.inventory.endpoints)} endpoints mapped; "
                f"{len(self.inventory.report())} zombie/shadow endpoints reported")
        self.fraud_hits = fraud.scan(self.feed.logs)
        n = sum(1 for v in self.fraud_hits.values() if v)
        self._t("fraud", f"fraud signals over 90 days: {n} of 6 signals firing")
        self.sweep("cold-start full sweep", [r["id"] for r in self.catalogue], since=time.time() - 30 * 86400)

    def validate(self, only: set[str] | None = None) -> None:
        """One safe L0 request per GET endpoint per identity, through the gate (PDF §8 validation)."""
        for ep in list(self.inventory.endpoints.values()):
            if ep.method != "GET" or (only is not None and ep.path not in only):
                continue
            url = HOST + ep.path.replace("{bookingId}", "1001").replace("{invoiceId}", "1").replace("{id}", "1")
            for handle in (None, self.handles["A.agent"]):
                try:
                    res = self.gate.request(GateRequest("GET", url, handle=handle, tier="L0", test_id="discovery-validate"))
                except GateBlocked:
                    continue
                self.inventory.add_validation("GET", ep.path, res["status"], handle is not None or res["status"] == 401, res["fields"])
                ev = self.detector.shape(ep.key + ("#auth" if handle else "#anon"), res["fields"], res["status"])
                if ev:
                    self.events.put(ev)

    # ---- planning + execution ---------------------------------------------------------------------
    def plan(self, routes: list[str]) -> list[dict]:
        known = {e.path for e in self.inventory.endpoints.values()}
        items = []
        for rule in self.catalogue:
            hit = [r for r in routes if any(r == x or r.startswith(x + "/") for x in RULE_ROUTES[rule["id"]])]
            if hit:
                items.append({"rule": rule["id"], "name": rule["name"], "tier": rule["tier"], "routes": hit,
                              "in_graph": all(h in known for h in hit), "owner": rule["owner"]})
        return items

    def sweep(self, trigger: str, rule_ids: list[str], since: float) -> list[dict]:
        found = []
        snap = self.feed.snap
        for rid in rule_ids:
            rule = next(r for r in self.catalogue if r["id"] == rid)
            cands = R.run(rule, snap, since)
            self.recorder.append("rule_check", {"rule": rid, "since": since, "candidates": len(cands), "trigger": trigger})
            if not cands:
                continue
            fresh = json.loads(json.dumps(snap))  # independent re-read of saved state
            ok = self.desk.verify(rid, cands, fresh, since)
            f = self.desk.triage(rid, ok, self.inventory, self.fraud_hits, 90, trigger)
            if f:
                found.append(f)
                self._t("finding", f"{f['id']} {f['severity']}: {f['title']} (₹{f['inr_observed']:,})", finding=f["id"])
        return found

    def handle(self, ev: ChangeEvent) -> None:
        t0 = time.time()
        self.runs += 1
        self._t("event", f"{ev.kind}: {ev.detail or ev.service}" + (f" [{ev.release}]" if ev.release else ""), routes=ev.routes)
        # refresh the other signals
        bev = self.detector.bundle(self.feed.js_bundle())
        if bev:
            self.inventory.add_js_bundle(self.feed.js_bundle())
            self._t("event", f"bundle: {bev.detail}", routes=bev.routes)
        if ev.kind == "dns-report":
            return
        # change window starts after the last stored record; then simulate minutes of post-deploy traffic
        since = max(ev.ts, self.feed.last_ts + 0.001)
        self.feed.advance(16, at=since + 1)
        lev = self.detector.logs(self.feed.logs[-400:])
        self.inventory.add_gateway_logs(self.feed.logs[-400:])
        if lev:
            self._t("event", f"traffic: {lev.detail}", routes=lev.routes)
        routes = sorted(set(ev.routes) | set(bev.routes if bev else []) | set(lev.routes if lev else []))
        self.validate(set(routes))
        self.inventory.classify()
        items = self.plan(routes)
        self.plans.insert(0, {"ts": time.time(), "trigger": ev.release or ev.kind, "items": items})
        self.plans = self.plans[:10]
        self._t("plan", f"planner: {len(items)} targeted checks for {len(routes)} changed routes",
                rules=[i["rule"] for i in items])
        self.fraud_hits = fraud.scan(self.feed.logs)
        found = self.sweep(f"{ev.kind} {ev.release or ''}".strip(), [i["rule"] for i in items], since=since)
        closed = self.desk.retest(set(routes), self.feed.snap, since=since, skip={f["id"] for f in found})
        for f in closed:
            self._t("retest", f"{f['id']} {f['status']}: {f['retest']}", finding=f["id"])
        self._t("done", f"run finished in {time.time() - t0:.1f}s · {len(found)} new finding(s)", seconds=time.time() - t0)

    # ---- organiser-side simulation ------------------------------------------------------------------
    def simulate_deploy(self, release: str) -> dict:
        payload = self.feed.deploy(release)
        body = json.dumps(payload).encode()
        return {"body": body, "signature": sign(self.secret, body), "payload": payload}

    def receive_webhook(self, body: bytes, signature: str) -> dict:
        payload = json.loads(body)
        ev = self.detector.webhook(body, signature, payload)
        self.recorder.append("webhook", {"service": payload.get("service"), "release": payload.get("release"), "accepted": bool(ev)})
        if ev:
            self.events.put(ev)
        return {"accepted": bool(ev)}

    def add_host(self, host: str) -> list[str]:
        self.feed.add_host(host)
        evs = self.detector.dns(self.feed.dns())
        for e in evs:
            self._t("event", e.detail)
            if e.kind == "dns":
                self.events.put(e)
        return [e.detail for e in evs]

    # ---- safety drills (PDF §15 test protocol step 3) ---------------------------------------------
    def drill(self, name: str) -> dict:
        if name == "out_of_scope":
            out = []
            for url in ("http://169.254.169.254/latest/meta-data/", "https://partner-legacy.tbo.example/api",
                        HOST + "/__control/deploy"):
                try:
                    self.gate.request(GateRequest("GET", url, tier="L0", test_id="drill-scope"))
                    out.append({"url": url, "result": "FORWARDED"})
                except GateBlocked as b:
                    out.append({"url": url, "result": f"blocked {b.check}: {b.reason}"})
            self._t("drill", "out-of-scope drill: " + "; ".join(o["result"].split(":")[0] for o in out))
            return {"results": out}
        if name == "latency":
            self.stub.extra_latency = 0.06
            before = self.gate.rate_factor
            url = HOST + "/api/v2/wallet"
            for _ in range(8):
                self.gate.request(GateRequest("GET", url, handle=self.handles["A.agent"], tier="L0", test_id="drill-latency"))
            self.stub.extra_latency = 0.0
            self._t("drill", f"latency drill: rate factor {before:.2f} → {self.gate.rate_factor:.2f}")
            return {"rate_before": before, "rate_after": self.gate.rate_factor, "backoffs": self.gate.counters["backoffs"]}
        if name == "recorder_outage":
            self.recorder.available = False
            try:
                self.gate.request(GateRequest("GET", HOST + "/api/v2/wallet", handle=self.handles["A.agent"], test_id="drill-recorder"))
                res = "FORWARDED"
            except GateBlocked as b:
                res = f"refused {b.check}: {b.reason}"
            self.recorder.available = True
            self.paused = False
            self._t("drill", f"recorder outage drill: {res}")
            return {"result": res}
        if name == "unsafe_write":
            out = []
            for req in (GateRequest("POST", HOST + "/api/v2/bookings", handle=self.handles["A.agent"], tier="L2",
                                    json_body={"quote_id": "Q1", "remarks": "real customer"}, test_id="drill-write"),
                        GateRequest("POST", HOST + "/api/v2/bookings", handle=self.handles["A.agent"], tier="L2",
                                    json_body={"quote_id": "Q1", "remarks": "VOYEGE-SYNTH"}, test_id="drill-write"),
                        GateRequest("POST", HOST + "/api/v2/bookings/1/refunds", handle=self.handles["A.agent"], tier="L3",
                                    json_body={"remarks": "VOYEGE-SYNTH"}, cleanup_registered=True, concurrency=True,
                                    test_id="drill-write")):
                try:
                    self.gate.request(req)
                    out.append("FORWARDED")
                except GateBlocked as b:
                    out.append(f"blocked {b.check}: {b.reason}")
            self._t("drill", "unsafe-write drill: " + "; ".join(o.split(":")[0] for o in out))
            return {"results": out}
        raise KeyError(name)

    def resume(self) -> None:
        self.paused = False
        self.gate.release("operator")
        self._t("resume", "operator resumed pipeline")

    # ---- view -----------------------------------------------------------------------------------
    def state(self) -> dict:
        findings = sorted(self.desk.findings.values(), key=lambda f: (-f["score"], f["id"]))
        eps = sorted((e.to_dict() for e in self.inventory.endpoints.values()), key=lambda e: e["key"])
        hb = time.time() - self.heartbeat
        return {
            "release": self.feed.release, "paused": self.paused, "runs": self.runs, "queue": self.events.qsize(),
            "heartbeat_age": round(hb, 1), "heartbeat_ok": hb < 30,
            "gate": self.gate.status(), "recorder": self.recorder.verify(),
            "findings": findings, "inventory": eps, "zombie_shadow": self.inventory.report(),
            "fraud": {k: {"desc": fraud.SIGNALS[k], "hits": v[:5], "count": len(v)} for k, v in self.fraud_hits.items()},
            "timeline": self.timeline[-60:][::-1], "plans": self.plans[:3], "alarms": self.alarms[-10:][::-1],
            "forgotten_hosts": self.detector.forgotten_hosts, "handles": self.vault.handles(),
            "catalogue": self.catalogue, "approvals": list(self.desk.approvals.values()),
        }
