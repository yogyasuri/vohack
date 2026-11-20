"""Business-rule engine (PDF Part A §9, Part B §4D): invariants as test oracles.

Each rule turns "is this fraud?" into a yes/no check over *persisted state* (N4 in §4F): bookings, payments,
refunds, coupon counters, wallet ledger, holds and supplier confirmations. Checks are read-only (L0) over a
records snapshot that the platform exports; a `since` timestamp scopes a check to records created after a
change, which is what the retest uses.

A violation carries the object IDs, the ₹ delta and the evidence fields needed to reproduce it, and nothing
else (minimum evidence).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field


@dataclass
class Violation:
    rule_id: str
    object_id: str
    agency: str
    delta_inr: float
    detail: str
    evidence: dict = field(default_factory=dict)
    endpoint: str = ""


def _since(rows, since):
    return [r for r in rows if r.get("ts", 0) >= since]


def _paid(snap):
    paid = defaultdict(float)
    for p in snap["payments"]:
        if p["status"] == "captured":
            paid[p["booking_id"]] += p["amount"]
    return paid


def inv_m1(snap, rule, since=0):
    quotes = {q["id"]: q for q in snap["quotes"]}
    out = []
    for b in _since(snap["bookings"], since):
        q = quotes.get(b["quote_id"])
        if q and abs(b["charged"] - q["total"]) > 0.5:
            out.append(Violation(rule["id"], b["id"], b["agency"], q["total"] - b["charged"],
                                 f"charged ₹{b['charged']:,.0f} but server quote was ₹{q['total']:,.0f}",
                                 {"booking": b["id"], "quote": q["id"], "charged": b["charged"], "quoted": q["total"]},
                                 "POST /api/v2/bookings"))
    return out


def inv_m10(snap, rule, since=0):
    lo, hi = rule.get("range_percent", [0, 25])
    out = []
    for m in _since(snap["markup_changes"], since):
        bad_role = m["by_role"] not in rule.get("allowed_roles", ["admin"])
        bad_range = not (lo <= m["percent"] <= hi)
        if bad_role or bad_range:
            why = []
            if bad_role:
                why.append(f"set by role '{m['by_role']}'")
            if bad_range:
                why.append(f"{m['percent']}% outside {lo}–{hi}%")
            out.append(Violation(rule["id"], m["id"], m["agency"], m.get("est_margin_inr", 0),
                                 "markup " + " and ".join(why),
                                 {"change": m["id"], "role": m["by_role"], "percent": m["percent"]},
                                 "PUT /api/v2/agency/markup"))
    return out


def inv_m2(snap, rule, since=0):
    paid = _paid(snap)
    refunded = defaultdict(float)
    latest = {}
    for r in snap["refunds"]:
        refunded[r["booking_id"]] += r["amount"]
        latest[r["booking_id"]] = max(latest.get(r["booking_id"], 0), r.get("ts", 0))
    agency = {b["id"]: b["agency"] for b in snap["bookings"]}
    out = []
    for bid, total in refunded.items():
        if latest[bid] >= since and total > paid.get(bid, 0) + 0.5:
            out.append(Violation(rule["id"], bid, agency.get(bid, "?"), total - paid.get(bid, 0),
                                 f"refunded ₹{total:,.0f} against ₹{paid.get(bid, 0):,.0f} paid",
                                 {"booking": bid, "refunded": total, "paid": paid.get(bid, 0)},
                                 "POST /api/v2/bookings/{bookingId}/refunds"))
    return out


def inv_m7(snap, rule, since=0):
    by_booking = defaultdict(list)
    for r in snap["refunds"]:
        by_booking[r["booking_id"]].append(r)
    agency = {b["id"]: b["agency"] for b in snap["bookings"]}
    out = []
    for bid, rows in by_booking.items():
        if len(rows) > 1 and max(r.get("ts", 0) for r in rows) >= since:
            dup = sorted(rows, key=lambda r: r["ts"])[1:]
            out.append(Violation(rule["id"], bid, agency.get(bid, "?"), sum(r["amount"] for r in dup),
                                 f"{len(rows)} refunds for one cancellation",
                                 {"booking": bid, "refund_ids": [r["id"] for r in rows],
                                  "gap_ms": int((rows[-1]["ts"] - rows[0]["ts"]) * 1000)},
                                 "POST /api/v2/bookings/{bookingId}/refunds"))
    return out


def inv_m3(snap, rule, since=0):
    instrument = {p["booking_id"]: p["instrument"] for p in snap["payments"] if p["status"] == "captured"}
    agency = {b["id"]: b["agency"] for b in snap["bookings"]}
    out = []
    for r in _since(snap["refunds"], since):
        src = instrument.get(r["booking_id"])
        if r["destination"] not in (src, "agency_wallet"):
            out.append(Violation(rule["id"], r["id"], agency.get(r["booking_id"], "?"), r["amount"],
                                 f"refund sent to '{r['destination']}', paid with '{src}'",
                                 {"refund": r["id"], "booking": r["booking_id"]},
                                 "POST /api/v2/bookings/{bookingId}/refunds"))
    return out


def inv_m4(snap, rule, since=0):
    paid = _paid(snap)
    out = []
    for b in _since(snap["bookings"], since):
        if b["status"] in ("confirmed", "ticketed") and paid.get(b["id"], 0) <= 0 and not b.get("credit_reserved"):
            out.append(Violation(rule["id"], b["id"], b["agency"], b["charged"],
                                 f"booking {b['status']} with no captured payment or reserved credit",
                                 {"booking": b["id"], "status": b["status"]},
                                 "POST /api/v2/bookings/{bookingId}/confirm"))
    return out


def inv_c1(snap, rule, since=0):
    out = []
    for c in snap["coupons"]:
        recent = [x for x in c["redemptions"] if x.get("ts", 0) >= since]
        if len(c["redemptions"]) > c["limit"] and recent:
            extra = len(c["redemptions"]) - c["limit"]
            out.append(Violation(rule["id"], c["code"], c.get("agency", "all"), extra * c["value"],
                                 f"redeemed {len(c['redemptions'])}× against limit {c['limit']}",
                                 {"coupon": c["code"], "redemptions": len(c["redemptions"]), "limit": c["limit"]},
                                 "POST /api/v2/coupons/redeem"))
    return out


def inv_m8(snap, rule, since=0):
    out = []
    for q in _since(snap["quotes"], since):
        if q["nights"] <= 0 or q["guests"] <= 0 or q["total"] <= 0:
            out.append(Violation(rule["id"], q["id"], q["agency"], abs(q.get("list_total", 0) - q["total"]),
                                 f"nights={q['nights']} guests={q['guests']} total=₹{q['total']:,.0f}",
                                 {"quote": q["id"]}, "POST /api/v2/quotes"))
    return out


def inv_m5(snap, rule, since=0):
    out = []
    for w in snap["wallets"]:
        spent = -sum(e["amount"] for e in w["ledger"] if e["amount"] < 0)
        recent = any(e.get("ts", 0) >= since for e in w["ledger"])
        if spent > w["credit_limit"] + 0.5 and recent:
            out.append(Violation(rule["id"], f"wallet-{w['agency']}", w["agency"], spent - w["credit_limit"],
                                 f"spent ₹{spent:,.0f} against limit ₹{w['credit_limit']:,.0f}",
                                 {"agency": w["agency"], "spent": spent, "limit": w["credit_limit"]},
                                 "POST /api/v2/wallet/debit"))
        bal = sum(e["amount"] for e in w["ledger"])
        if abs(bal - w["balance"]) > 0.5 and recent:
            out.append(Violation(rule["id"], f"ledger-{w['agency']}", w["agency"], abs(bal - w["balance"]),
                                 f"stored balance ₹{w['balance']:,.0f} ≠ ledger sum ₹{bal:,.0f}",
                                 {"agency": w["agency"]}, "GET /api/v2/wallet"))
    return out


def inv_s2(snap, rule, since=0):
    cap, max_min = rule.get("max_holds_per_agency", 10), rule.get("max_hold_minutes", 30)
    active = Counter(h["agency"] for h in snap["holds"] if h["status"] == "held")
    out = [Violation(rule["id"], f"holds-{a}", a, 0, f"{n} active holds (cap {cap})", {"agency": a, "holds": n},
                     "POST /api/v2/holds") for a, n in active.items() if n > cap]
    for h in _since(snap["holds"], since):
        if h["minutes"] > max_min:
            out.append(Violation(rule["id"], h["id"], h["agency"], 0, f"hold lived {h['minutes']} min (max {max_min})",
                                 {"hold": h["id"]}, "POST /api/v2/holds"))
    return out


def inv_r1(snap, rule, since=0):
    paid = _paid(snap)
    sup = {s["booking_id"]: s for s in snap["supplier"]}
    out = []
    for b in _since(snap["bookings"], since):
        s = sup.get(b["id"])
        if b["status"] in ("confirmed", "ticketed"):
            if not s or s["status"] != "confirmed":
                out.append(Violation(rule["id"], b["id"], b["agency"], b["charged"],
                                     "platform confirmed but supplier did not", {"booking": b["id"]},
                                     "POST /api/v2/bookings"))
            elif abs(s["price"] - b["charged"]) > 0.5 and paid.get(b["id"]):
                out.append(Violation(rule["id"], b["id"], b["agency"], abs(s["price"] - b["charged"]),
                                     f"supplier price ₹{s['price']:,.0f} ≠ charged ₹{b['charged']:,.0f}",
                                     {"booking": b["id"]}, "POST /api/v2/bookings"))
    return out


CHECKS = {"INV-M1": inv_m1, "INV-M10": inv_m10, "INV-M2": inv_m2, "INV-M7": inv_m7, "INV-M3": inv_m3,
          "INV-M4": inv_m4, "INV-C1": inv_c1, "INV-M8": inv_m8, "INV-M5": inv_m5, "INV-S2": inv_s2,
          "INV-R1": inv_r1}

# Known-good control record per rule: the verifier confirms the oracle says "holds" on it, so a finding
# cannot come from an oracle that flags everything.
CONTROLS = {
    "INV-M1": {"quotes": [{"id": "CQ", "agency": "C", "total": 1000, "nights": 1, "guests": 1}],
               "bookings": [{"id": "CB", "agency": "C", "quote_id": "CQ", "charged": 1000, "status": "confirmed"}]},
    "INV-M2": {"payments": [{"booking_id": "CB", "amount": 1000, "status": "captured", "instrument": "card"}],
               "refunds": [{"id": "CR", "booking_id": "CB", "amount": 800, "destination": "card", "ts": 0}],
               "bookings": [{"id": "CB", "agency": "C"}]},
}


def empty_snapshot() -> dict:
    return {k: [] for k in ("quotes", "bookings", "payments", "refunds", "coupons", "markup_changes",
                            "wallets", "holds", "supplier")}


def run(rule: dict, snapshot: dict, since: float = 0) -> list[Violation]:
    return CHECKS[rule["id"]](snapshot, rule, since)


def control_holds(rule: dict) -> bool:
    snap = {**empty_snapshot(), **CONTROLS.get(rule["id"], {})}
    return not CHECKS[rule["id"]](snap, rule, 0)
