"""Synthetic organiser inputs for the prototype (PDF Part B §4E "every provided input has a job").

Stands in for what the hackathon organisers provide: HAR files, the front-end bundle, 30-90 days of gateway
logs, DNS/CT hostnames, ownership data, deploy events, and a read-only export of platform records. All data
is synthetic (fake agencies, travellers and amounts). A "release" changes how the simulated platform writes
new records, so the deploy → detect → ticket → fix → retest loop can run end to end without touching any
real system.
"""
from __future__ import annotations

import random
import time

from .rules import empty_snapshot

DAY = 86400
AGENCIES = ["A", "B", "C"]
HOST = "https://api.staging.tbo.test"

BASE_ROUTES = [
    ("GET", "/api/v2/search"), ("POST", "/api/v2/quotes"), ("POST", "/api/v2/holds"),
    ("POST", "/api/v2/bookings"), ("GET", "/api/v2/bookings/{id}"), ("POST", "/api/v2/bookings/{id}/pay"),
    ("POST", "/api/v2/bookings/{id}/cancel"), ("POST", "/api/v2/bookings/{id}/refunds"),
    ("POST", "/api/v2/coupons/redeem"), ("GET", "/api/v2/wallet"), ("PUT", "/api/v2/agency/markup"),
    ("POST", "/api/v2/auth/login"), ("GET", "/api/v2/invoices/{id}"), ("POST", "/api/v2/bookings/{id}/confirm"),
]

RELEASES = {
    "r2.4.0": {"notes": "baseline", "broken": {"INV-C1", "INV-M4"}, "extra_routes": []},
    "r2.5.0": {"notes": "refunds: partial refunds with client-supplied amount", "service": "refunds-svc",
               "broken": {"INV-C1", "INV-M4", "INV-M2"},
               "extra_routes": [("GET", "/api/v2/bookings/{id}/refunds/preview")],
               "routes": ["/api/v2/bookings/{bookingId}/refunds", "/api/v2/bookings/{bookingId}/refunds/preview"]},
    "r2.5.1": {"notes": "refunds: server computes refundable amount", "service": "refunds-svc",
               "broken": {"INV-C1", "INV-M4"},
               "extra_routes": [("GET", "/api/v2/bookings/{id}/refunds/preview")],
               "routes": ["/api/v2/bookings/{bookingId}/refunds"]},
    "r2.5.2": {"notes": "promotions: atomic coupon counter; booking: payment gate", "service": "promo-svc",
               "broken": set(), "extra_routes": [("GET", "/api/v2/bookings/{id}/refunds/preview")],
               "routes": ["/api/v2/coupons/redeem", "/api/v2/bookings/{bookingId}/confirm"]},
}


class SyntheticFeed:
    def __init__(self, seed: int = 7, now: float | None = None):
        self.rng = random.Random(seed)
        self.now = now or time.time()
        self.release = "r2.4.0"
        self.snap = empty_snapshot()
        self.logs: list[dict] = []
        self.hosts = ["staging.tbo.test", "api.staging.tbo.test"]
        self._n = 1000
        self.last_ts = 0.0
        self._coupons = {"WELCOME10": {"code": "WELCOME10", "limit": 3, "value": 750, "redemptions": [], "agency": "all"}}
        self.snap["coupons"] = list(self._coupons.values())
        self.snap["wallets"] = [{"agency": a, "credit_limit": 500000, "ledger": [], "balance": 0} for a in AGENCIES]
        self._history()

    # ---- inputs ---------------------------------------------------------------------------------
    def routes(self):
        return BASE_ROUTES + RELEASES[self.release]["extra_routes"]

    def js_bundle(self) -> str:
        calls = "\n".join(f'  api.{m.lower()}("{p.replace("{id}", "${id}")}");' for m, p in self.routes())
        return f"// app.{self.release}.js (synthetic)\nexport function routes(api, id) {{\n{calls}\n}}\n"

    def har(self, agency: str = "A", role: str = "agent") -> dict:
        def entry(method, path, body=None, resp=None):
            e = {"request": {"method": method, "url": HOST + path, "headers": [{"name": "Authorization", "value": "Bearer <redacted>"}],
                             "queryString": [{"name": "city", "value": "GOA"}] if path.endswith("search") else []},
                 "response": {"status": 200, "content": {"text": __import__("json").dumps(resp or {"id": "X"})}}}
            if body:
                e["request"]["postData"] = {"text": __import__("json").dumps(body)}
            return e
        return {"log": {"entries": [
            entry("GET", "/api/v2/search", resp={"items": [], "city": "GOA"}),
            entry("POST", "/api/v2/quotes", {"hotel_id": "H1", "nights": 2, "guests": 2}, {"id": "Q1", "total": 9000, "currency": "INR", "expires_at": 0}),
            entry("POST", "/api/v2/holds", {"quote_id": "Q1"}, {"id": "HD1", "status": "held"}),
            entry("POST", "/api/v2/bookings", {"quote_id": "Q1", "coupon": "WELCOME10"}, {"id": "BK1", "status": "pending_payment", "amount": 9000}),
            entry("POST", "/api/v2/bookings/1001/pay", {"method": "test_card"}, {"id": "BK1", "status": "captured"}),
            entry("GET", "/api/v2/bookings/1001", resp={"id": "BK1", "agency_id": agency, "traveller_name": "Test Person", "amount": 9000, "status": "confirmed"}),
        ]}}

    def dns(self) -> list[str]:
        return list(self.hosts)

    # ---- releases -------------------------------------------------------------------------------
    def deploy(self, release: str) -> dict:
        self.release = release
        r = RELEASES[release]
        return {"service": r.get("service", "platform"), "release": release, "notes": r["notes"],
                "routes": r.get("routes", []), "force": True}

    def add_host(self, host: str) -> None:
        if host not in self.hosts:
            self.hosts.append(host)

    # ---- traffic simulation ---------------------------------------------------------------------
    def advance(self, n: int = 12, at: float | None = None) -> None:
        t = at or time.time()
        broken = RELEASES[self.release]["broken"]
        for i in range(n):
            self._txn(t + i * 0.5, broken)
        self._route_traffic(t, days=1, scale=1)

    def _history(self) -> None:
        start = self.now - 90 * DAY
        for d in range(90):
            day = start + d * DAY
            self._route_traffic(day, days=1, scale=1)
            for _ in range(4):
                self._txn(day + self.rng.uniform(0, DAY), RELEASES["r2.4.0"]["broken"] if d > 60 else set())
        # zombie: old v1 route, unauthenticated, last real call 75 days ago
        for k in range(6):
            self.logs.append(self._row(start + k * DAY, "GET", f"/api/v1/bookings/{900 + k}", auth=False, role="agent"))
        # shadow: partner API used daily but never in HAR or bundle
        for d in range(90):
            self.logs.append(self._row(start + d * DAY + 3600, "GET", "/api/v2/partner/availability", role="partner"))
        # historical markup change by a sub-agent (INV-M10), and a hold spike for agency C
        self.snap["markup_changes"].append({"id": "MK-77", "agency": "B", "by_role": "subagent", "percent": 32,
                                            "est_margin_inr": 41000, "ts": self.now - 12 * DAY})
        spike = self.now - 3 * DAY
        for k in range(14):
            self.snap["holds"].append({"id": f"HS-{k}", "agency": "C", "minutes": 25, "status": "held", "ts": spike + k * 60})
            self.logs.append({**self._row(spike + k * 60, "POST", "/api/v2/holds", role="agent", agency="C"), "event": "hold_created"})
        # an account reading other agencies' bookings (seen in logs only)
        for k in range(4):
            self.logs.append({**self._row(self.now - 5 * DAY + k * 30, "GET", f"/api/v2/bookings/{2000 + k}", role="agent", agency="A"),
                              "account": "agent-a-17", "object_agency": "B", "object_id": f"BK{2000 + k}"})
        # our own test traffic: must be excluded from inventory and signals
        self.logs.append({**self._row(self.now - 3600, "GET", "/api/v1/bookings/1", auth=False), "account": "vtest-a-agent"})

    def _route_traffic(self, day: float, days: int, scale: int) -> None:
        for m, p in self.routes():
            for _ in range(scale):
                path = p.replace("{id}", str(self.rng.randint(1000, 9999)))
                self.logs.append(self._row(day + self.rng.uniform(0, DAY * days * 0.9), m, path, role="agent"))

    def _row(self, ts, method, path, auth=True, role="agent", agency=None) -> dict:
        agency = agency or self.rng.choice(AGENCIES)
        return {"ts": ts, "method": method, "path": path, "status": 200, "auth": auth, "role": role,
                "agency": agency, "account": f"{role}-{agency.lower()}-{self.rng.randint(1, 40)}", "ua": "Mozilla/5.0"}

    def _txn(self, ts: float, broken: set) -> None:
        r = self.rng
        self._n += 1
        self.last_ts = max(self.last_ts, ts + 5)
        n, agency = self._n, r.choice(AGENCIES)
        nights, guests = r.randint(1, 5), r.randint(1, 3)
        total = float(nights * guests * r.choice([2400, 3100, 4800]))
        q = {"id": f"Q{n}", "agency": agency, "total": total, "nights": nights, "guests": guests, "currency": "INR",
             "list_total": total, "ts": ts}
        self.snap["quotes"].append(q)
        charged = round(total * 0.55) if "INV-M1" in broken and r.random() < 0.3 else total
        bid = f"BK{n}"
        skip_pay = "INV-M4" in broken and r.random() < 0.08
        b = {"id": bid, "agency": agency, "quote_id": q["id"], "charged": charged, "currency": "INR",
             "status": "confirmed", "ts": ts}
        self.snap["bookings"].append(b)
        self.logs.append({**self._row(ts, "POST", "/api/v2/bookings", agency=agency), "event": "booking_charged",
                          "object_id": bid, "amount": charged, "quoted": total})
        if skip_pay:
            self.logs.append({**self._row(ts + 1, "POST", f"/api/v2/bookings/{n}/confirm", agency=agency),
                              "event": "booking_confirmed", "object_id": bid})
        else:
            self.snap["payments"].append({"id": f"P{n}", "booking_id": bid, "amount": charged, "status": "captured",
                                          "instrument": "test_card", "ts": ts})
            self.logs.append({**self._row(ts + 1, "POST", f"/api/v2/bookings/{n}/pay", agency=agency),
                              "event": "payment_captured", "object_id": bid, "amount": charged})
        self.snap["supplier"].append({"booking_id": bid, "pnr": f"PNR{n}", "price": charged, "status": "confirmed"})
        w = next(x for x in self.snap["wallets"] if x["agency"] == agency)
        w["ledger"].append({"amount": -25.0, "ts": ts})  # platform service fee per booking
        w["balance"] = sum(e["amount"] for e in w["ledger"])
        if r.random() < 0.25:  # coupon use
            c = self._coupons["WELCOME10"]
            if "INV-C1" in broken or len(c["redemptions"]) < c["limit"]:
                c["redemptions"].append({"booking": bid, "ts": ts})
                self.logs.append({**self._row(ts + 2, "POST", "/api/v2/coupons/redeem", agency=agency),
                                  "event": "coupon_redeemed", "code": c["code"], "limit": c["limit"]})
        if r.random() < 0.35 and not skip_pay:  # cancellation + refund
            b["status"] = "cancelled"
            amt = round(charged * (1.4 if "INV-M2" in broken else 0.8))
            self.snap["refunds"].append({"id": f"RF{n}", "booking_id": bid, "amount": amt, "destination": "test_card", "ts": ts + 5})
            self.logs.append({**self._row(ts + 5, "POST", f"/api/v2/bookings/{n}/refunds", agency=agency),
                              "event": "refund_issued", "object_id": bid, "amount": amt})
