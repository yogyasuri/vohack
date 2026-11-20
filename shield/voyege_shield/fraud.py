"""Fraud signals in logs (PDF Part B §2A, the detection lens). Read-only; sends no traffic.

Six signals over the provided gateway/application logs. When a rule is proven broken, the matching signal is
searched over the log window and the ticket gets "Seen in traffic: yes / no / not checked".
"""
from __future__ import annotations

from collections import Counter, defaultdict

SIGNAL_FOR_RULE = {"INV-T1": "cross_agency_harvest", "INV-M2": "refund_over_paid", "INV-M7": "refund_over_paid",
                   "INV-C1": "coupon_over_limit", "INV-M1": "charged_vs_quoted", "INV-S2": "hold_spike",
                   "INV-M4": "ticket_without_payment"}

SIGNALS = {
    "cross_agency_harvest": "One account opening many other agencies' booking or invoice IDs",
    "refund_over_paid": "Refund total above payment total for a booking",
    "coupon_over_limit": "Same coupon redeemed beyond its limit",
    "charged_vs_quoted": "Charged amount differing from quoted amount",
    "hold_spike": "Sudden spike in holds or searches per agency",
    "ticket_without_payment": "Confirmation or ticket with no matching payment record",
}


def scan(rows: list[dict], window: tuple[float, float] | None = None) -> dict[str, list[dict]]:
    if window:
        rows = [r for r in rows if window[0] <= r["ts"] <= window[1]]
    hits: dict[str, list[dict]] = {k: [] for k in SIGNALS}

    foreign = defaultdict(set)
    for r in rows:
        if r.get("object_agency") and r.get("agency") and r["object_agency"] != r["agency"] and r["status"] < 400:
            foreign[r["account"]].add(r.get("object_id"))
    for acct, objs in foreign.items():
        if len(objs) >= 3:
            hits["cross_agency_harvest"].append({"account": acct, "foreign_objects": len(objs)})

    paid, refunded = defaultdict(float), defaultdict(float)
    for r in rows:
        ev = r.get("event")
        if ev == "payment_captured":
            paid[r["object_id"]] += r["amount"]
        elif ev == "refund_issued":
            refunded[r["object_id"]] += r["amount"]
    for bid, amt in refunded.items():
        if amt > paid.get(bid, 0) + 0.5:
            hits["refund_over_paid"].append({"booking": bid, "refunded": amt, "paid": paid.get(bid, 0)})

    redeemed, limits = Counter(), {}
    for r in rows:
        if r.get("event") == "coupon_redeemed":
            redeemed[r["code"]] += 1
            limits[r["code"]] = r.get("limit", 1)
    for code, n in redeemed.items():
        if n > limits[code]:
            hits["coupon_over_limit"].append({"coupon": code, "redemptions": n, "limit": limits[code]})

    for r in rows:
        if r.get("event") == "booking_charged" and abs(r["amount"] - r.get("quoted", r["amount"])) > 0.5:
            hits["charged_vs_quoted"].append({"booking": r["object_id"], "charged": r["amount"], "quoted": r["quoted"]})

    holds = defaultdict(Counter)
    for r in rows:
        if r.get("event") == "hold_created":
            holds[r["agency"]][int(r["ts"] // 3600)] += 1
    for agency, per_hour in holds.items():
        vals = sorted(per_hour.values())
        median = vals[len(vals) // 2] if vals else 0
        peak_hour, peak = max(per_hour.items(), key=lambda kv: kv[1])
        if peak >= max(10, 5 * max(1, median)):
            hits["hold_spike"].append({"agency": agency, "peak_per_hour": peak, "median": median})

    paid_ids = set(paid)
    for r in rows:
        if r.get("event") in ("booking_confirmed", "ticket_issued") and r["object_id"] not in paid_ids and not r.get("credit"):
            hits["ticket_without_payment"].append({"booking": r["object_id"], "event": r["event"]})
    return hits


def seen_in_traffic(rule_id: str, hits: dict[str, list[dict]] | None, window_days: int) -> dict:
    sig = SIGNAL_FOR_RULE.get(rule_id)
    if hits is None or not sig:
        return {"value": "not checked", "signal": sig, "window_days": window_days}
    return {"value": "yes" if hits.get(sig) else "no", "signal": sig, "window_days": window_days,
            "matches": len(hits.get(sig, []))}
