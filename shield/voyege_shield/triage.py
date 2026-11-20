"""Verifier, triage, tickets, approval desk and retest (PDF §13 components 9-12, Part B §4A outputs).

* Verifier: re-runs the rule on a fresh snapshot fetched independently, and runs the control (the oracle must
  say "holds" on a known-good record). Only then is a candidate `verified`. No model can set this flag.
* Triage: root-cause fingerprint for dedupe, severity = exploitability × impact × reach
  (Critical ≥ 24, High 12-23, Medium 6-11, Low < 6), ₹ at risk, owner from the inventory graph.
  "Seen in traffic: yes" raises severity one level and adds Finance/Fraud to the ticket.
* Tickets: Jira/GitHub-issue shaped JSON + markdown. Critical/High are held until a person confirms.
* Retest: after a deploy touching the endpoint, the rule is re-run on records created since the deploy;
  the ticket closes only if the rule holds *and* the control still passes.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

from . import rules as R
from .fraud import seen_in_traffic

LEVELS = ["Low", "Medium", "High", "Critical"]
FIX = {
    "INV-M1": "Recompute the amount server-side from the stored quote; ignore any client-sent price.",
    "INV-M10": "Enforce role check and policy bounds on markup/commission updates in the agency service.",
    "INV-M2": "Compute refundable = paid − fees − prior refunds on the server; reject larger amounts.",
    "INV-M7": "Take a row lock on the booking and check refund state inside the same transaction.",
    "INV-M3": "Refund only to the original payment instrument or agency wallet; drop client destinations.",
    "INV-M4": "Gate confirm/ticket transitions on captured payment or reserved credit in the state machine.",
    "INV-C1": "Use an atomic conditional increment (UPDATE … WHERE redemptions < limit) for coupon counts.",
    "INV-M8": "Validate quantities and money fields are positive and within bounds before pricing.",
    "INV-M5": "Atomic debit with a balance check under lock; reconcile ledger sum = stored balance daily.",
    "INV-S2": "Enforce per-agency hold caps and a maximum hold lifetime on the server.",
    "INV-R1": "Add a reconciliation job with compensations for supplier/platform mismatches.",
}
EXPLOITABILITY = {"INV-M1": 3, "INV-M10": 2, "INV-M2": 3, "INV-M7": 1, "INV-M3": 2, "INV-M4": 3,
                  "INV-C1": 3, "INV-M8": 3, "INV-M5": 1, "INV-S2": 3, "INV-R1": 1}


def severity(exploit: int, impact: int, reach: int) -> tuple[int, str]:
    score = exploit * impact * reach
    return score, "Critical" if score >= 24 else "High" if score >= 12 else "Medium" if score >= 6 else "Low"


def fingerprint(rule_id: str, endpoint: str) -> str:
    return hashlib.sha1(f"{rule_id}|{endpoint}".encode()).hexdigest()[:10]


class FindingDesk:
    def __init__(self, catalogue: list[dict], out_dir: str | Path, recorder=None):
        self.rules = {r["id"]: r for r in catalogue}
        self.findings: dict[str, dict] = {}
        self.approvals: dict[str, dict] = {}
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.recorder = recorder

    # ---- verify ---------------------------------------------------------------------------------
    def verify(self, rule_id: str, candidates: list[R.Violation], fresh_snapshot: dict, since: float) -> list[R.Violation]:
        rule = self.rules[rule_id]
        if not R.control_holds(rule):
            return []  # oracle flags known-good data: suspicion only, never reported
        again = {v.object_id for v in R.run(rule, fresh_snapshot, since)}
        return [v for v in candidates if v.object_id in again]

    # ---- triage ---------------------------------------------------------------------------------
    def triage(self, rule_id: str, violations: list[R.Violation], inventory, fraud_hits, window_days: int,
               trigger: str) -> dict | None:
        if not violations:
            return None
        rule = self.rules[rule_id]
        endpoint = violations[0].endpoint
        fp = fingerprint(rule_id, endpoint)
        agencies = {v.agency for v in violations}
        reach = 3 if len(agencies) >= 3 or "all" in agencies else 2 if len(agencies) == 2 else 1
        score, sev = severity(EXPLOITABILITY.get(rule_id, 2), rule["impact"], reach)
        seen = seen_in_traffic(rule_id, fraud_hits, window_days)
        if seen["value"] == "yes" and sev != "Critical":
            sev = LEVELS[LEVELS.index(sev) + 1]
        ep = inventory.endpoints.get(endpoint) if inventory else None
        owner = (ep.owner if ep and ep.owner_confidence >= 0.6 else None) or rule["owner"]
        delta = sum(max(0, v.delta_inr) for v in violations)
        per_day = (ep.hits_30d / 30) if ep and ep.hits_30d else 1
        existing = self.findings.get(fp)
        if existing and existing["status"] not in ("closed",):
            existing["occurrences"] += len(violations)
            existing["last_seen"] = time.time()
            return None  # duplicate of an open root cause
        f = {
            "id": f"VYG-{len(self.findings) + 101}", "fingerprint": fp, "rule_id": rule_id, "title": rule["name"],
            "class": "fraud / business logic", "endpoint": endpoint, "owner": owner,
            "cc": ["Finance", "Fraud"] if seen["value"] == "yes" else [],
            "severity": sev, "score": score, "formula": f"{EXPLOITABILITY.get(rule_id, 2)} × {rule['impact']} × {reach} = {score}",
            "inr_observed": round(delta), "inr_at_risk_30d": round(delta / max(1, len(violations)) * per_day * 30),
            "agencies": sorted(agencies), "occurrences": len(violations), "seen_in_traffic": seen,
            "evidence": [v.evidence for v in violations[:3]], "details": list(dict.fromkeys(v.detail for v in violations))[:3],
            "reproduction": [f"Export records for {endpoint} since the trigger",
                             f"Evaluate {rule_id}: {rule['name']}",
                             f"Objects breaking it: {', '.join(v.object_id for v in violations[:3])}",
                             "Control: the same check on a known-good record holds"],
            "fix": FIX.get(rule_id, "See rule catalogue."), "tier": rule["tier"], "trigger": trigger,
            "status": "awaiting_approval" if sev in ("Critical", "High") else "open",
            "verified": True, "created": time.time(), "last_seen": time.time(), "retest": "pending next deploy",
            "history": [{"ts": time.time(), "status": "verified", "by": "verifier"}],
        }
        self.findings[fp] = f
        if f["status"] == "open":
            self._emit(f)
        self._log("finding", {"id": f["id"], "rule": rule_id, "severity": sev, "status": f["status"]})
        return f

    # ---- approval desk --------------------------------------------------------------------------
    def approve(self, finding_id: str, who: str, decision: str = "approve") -> dict:
        f = self._by_id(finding_id)
        if f["status"] != "awaiting_approval":
            return f
        f["status"] = "open" if decision == "approve" else "rejected"
        f["history"].append({"ts": time.time(), "status": f["status"], "by": who})
        self._log("approval", {"finding": finding_id, "by": who, "decision": decision})
        if f["status"] == "open":
            self._emit(f)
        return f

    def grant_batch(self, purpose: str, who: str, minutes: int = 60) -> dict:
        a = {"id": "APR-" + uuid.uuid4().hex[:6], "purpose": purpose, "by": who, "expires": time.time() + minutes * 60}
        self.approvals[a["id"]] = a
        self._log("approval_batch", a)
        return a

    def approval_valid(self, approval_id: str) -> bool:
        a = self.approvals.get(approval_id)
        return bool(a and a["expires"] > time.time())

    # ---- retest ---------------------------------------------------------------------------------
    def retest(self, touched_routes: set[str], snapshot: dict, since: float, skip: set[str] = frozenset()) -> list[dict]:
        changed = []
        for f in self.findings.values():
            if f["status"] not in ("open", "awaiting_approval") or f["id"] in skip:
                continue
            if touched_routes and f["endpoint"].split(" ", 1)[-1] not in touched_routes:
                continue
            rule = self.rules[f["rule_id"]]
            still = R.run(rule, snapshot, since)
            if not still and R.control_holds(rule):
                f["status"], f["retest"] = "closed", "passed: rule holds on post-deploy records; control passes"
                f["history"].append({"ts": time.time(), "status": "closed", "by": "retest"})
            else:
                f["retest"] = f"failed: {len(still)} new violation(s) after deploy"
                f["history"].append({"ts": time.time(), "status": "retest-failed", "by": "retest"})
            self._log("retest", {"finding": f["id"], "result": f["retest"]})
            self._emit(f)
            changed.append(f)
        return changed

    # ---- output ---------------------------------------------------------------------------------
    def _emit(self, f: dict) -> None:
        ticket = {"title": f"[{f['severity']}] {f['title']} — {f['endpoint']}", "labels": ["voyege", f["rule_id"], f["severity"].lower()],
                  "assignee_team": f["owner"], "cc": f["cc"], "body": self.markdown(f), "finding": f}
        (self.out / f"{f['id']}.json").write_text(json.dumps(ticket, indent=2, default=str))
        (self.out / f"{f['id']}.md").write_text(self.markdown(f))

    @staticmethod
    def markdown(f: dict) -> str:
        s = f["seen_in_traffic"]
        return "\n".join([
            f"## {f['id']} · {f['title']}", "",
            f"**Severity:** {f['severity']} ({f['formula']}) · **Owner:** {f['owner']} · **Rule:** {f['rule_id']}",
            f"**Endpoint:** `{f['endpoint']}` · **Agencies affected:** {', '.join(f['agencies'])}",
            f"**₹ observed:** {f['inr_observed']:,} · **₹ at risk (30 d est.):** {f['inr_at_risk_30d']:,}",
            f"**Seen in traffic:** {s['value']} (signal `{s.get('signal')}`, last {s['window_days']} days)", "",
            "### What is broken", *[f"- {d}" for d in f["details"]], "",
            "### Reproduce", *[f"{i}. {r}" for i, r in enumerate(f["reproduction"], 1)], "",
            "### Fix", f["fix"], "", f"**Retest:** {f['retest']} · **Status:** {f['status']}", ""])

    def _by_id(self, fid: str) -> dict:
        for f in self.findings.values():
            if f["id"] == fid:
                return f
        raise KeyError(fid)

    def _log(self, kind: str, data: dict) -> None:
        if self.recorder:
            try:
                self.recorder.append(kind, data)
            except Exception:
                pass
