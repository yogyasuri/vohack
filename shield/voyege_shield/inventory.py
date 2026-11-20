"""Discovery & inventory graph (PDF Part A §8, Part B §4A/§5D).

Sources fused into one endpoint graph: HAR files, front-end JS bundles, gateway logs (30-90 days) and the
policy target list. Each endpoint records which sources saw it; disagreements between sources are exactly
the zombie and shadow APIs. Labels are deterministic rules, not model judgement.
"""
from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field

DAY = 86400
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[A-Z]{2,4}-?\d{3,}|[0-9a-f]{16,})$", re.I)
_JS_ROUTE = re.compile(r"""["'`](/(?:api|internal|v\d)[A-Za-z0-9_\-/{}:.$]*)["'`]""")
_JS_CALL = re.compile(r"\.(get|post|put|patch|delete)\(\s*[\"'`]$", re.I)
_VERSION = re.compile(r"/v(\d+)/")
_PARAM_NAMES = {"bookings": "bookingId", "refunds": "refundId", "invoices": "invoiceId", "quotes": "quoteId",
                "holds": "holdId", "coupons": "code", "travellers": "travellerId", "payments": "paymentId"}
MONEY_FIELDS = {"amount", "price", "fare", "markup", "commission", "total", "credit_limit", "discount"}
PII_FIELDS = {"passport", "email", "phone", "dob", "card", "traveller_name", "pan"}


def template(path: str) -> str:
    """`/api/v2/bookings/8812` -> `/api/v2/bookings/{bookingId}` using ID-shape detection."""
    path = path.split("?", 1)[0].rstrip("/") or "/"
    out, prev = [], ""
    for seg in path.split("/"):
        if seg and (_ID_SEGMENT.match(seg) or seg.startswith("${") or seg.startswith(":")):
            out.append("{" + _PARAM_NAMES.get(prev, "id") + "}")
        else:
            out.append(seg)
        prev = seg
    return "/".join(out)


@dataclass
class Endpoint:
    method: str
    path: str
    sources: set = field(default_factory=set)
    params: set = field(default_factory=set)
    response_fields: set = field(default_factory=set)
    auth_seen: set = field(default_factory=set)       # True / False observed in traffic
    roles_seen: set = field(default_factory=set)
    last_seen: float | None = None                    # last legitimate traffic
    hits_30d: int = 0
    hits_90d: int = 0
    owner: str | None = None
    service: str | None = None
    owner_confidence: float = 0.0
    labels: list = field(default_factory=list)
    recommendation: str | None = None
    reason: str | None = None

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict:
        d = asdict(self)
        for k in ("sources", "params", "response_fields", "auth_seen", "roles_seen"):
            d[k] = sorted(str(x) for x in d[k])
        d["key"] = self.key
        return d


class Inventory:
    def __init__(self, policy: dict, owners: dict):
        self.policy, self.owners = policy, owners
        self.endpoints: dict[str, Endpoint] = {}
        self.notes: list[dict] = []

    def _ep(self, method: str, path: str) -> Endpoint:
        t = template(path)
        key = f"{method.upper()} {t}"
        if key not in self.endpoints:
            self.endpoints[key] = Endpoint(method.upper(), t)
        return self.endpoints[key]

    # ---- sources --------------------------------------------------------------------------------
    def add_har(self, har: dict, role: str | None = None) -> int:
        n = 0
        for e in har.get("log", {}).get("entries", []):
            req, res = e["request"], e.get("response", {})
            url = req["url"]
            path = "/" + url.split("://", 1)[-1].split("/", 1)[-1] if "://" in url else url
            ep = self._ep(req["method"], path)
            ep.sources.add("har")
            for q in req.get("queryString", []):
                ep.params.add(q["name"])
            body = req.get("postData", {}).get("text")
            if body:
                try:
                    ep.params.update(json.loads(body).keys())
                except (ValueError, AttributeError):
                    pass
            ep.auth_seen.add(any(h["name"].lower() == "authorization" for h in req.get("headers", [])))
            if role:
                ep.roles_seen.add(role)
            text = res.get("content", {}).get("text")
            if text:
                try:
                    obj = json.loads(text)
                    if isinstance(obj, dict):
                        ep.response_fields.update(obj.keys())
                except ValueError:
                    pass
            n += 1
        return n

    def add_js_bundle(self, js: str) -> set[str]:
        """Static route extraction: string literals and fetch/axios calls. Method unknown -> GET assumed,
        refined when another source sees the same template."""
        found = set()
        for m in _JS_ROUTE.finditer(js):
            raw = re.sub(r"\$\{[^}]+\}", "1", m.group(1))
            t = template(raw)
            found.add(t)
            call = _JS_CALL.search(js[max(0, m.start() - 24):m.start() + 1])
            if call:
                methods = [call.group(1).upper()]
            else:
                methods = [k.split(" ", 1)[0] for k, e in self.endpoints.items() if e.path == t] or ["GET"]
            for meth in methods:
                self._ep(meth, t).sources.add("js")
        return found

    def add_gateway_logs(self, rows: list[dict], now: float | None = None) -> int:
        """rows: {ts, method, path, status, auth: bool, account, agency, role, ua}. Own test traffic excluded."""
        now = now or time.time()
        mark = self.policy["inventory"]["own_traffic_markers"]
        n = 0
        for r in rows:
            if str(r.get("account", "")).startswith(mark["account_prefix"]) or r.get("test_header"):
                continue
            if r.get("ua", "").startswith(("healthcheck", "scanner")):
                continue
            ep = self._ep(r["method"], r["path"])
            ep.sources.add("logs")
            ep.auth_seen.add(bool(r.get("auth")))
            if r.get("role"):
                ep.roles_seen.add(r["role"])
            ts = r["ts"]
            ep.last_seen = max(ep.last_seen or 0, ts)
            if now - ts <= 30 * DAY:
                ep.hits_30d += 1
            if now - ts <= 90 * DAY:
                ep.hits_90d += 1
            n += 1
        return n

    def add_validation(self, method: str, path: str, status: int, auth_required: bool, fields: list[str]) -> None:
        """One safe request per role (through the gate) confirms the endpoint answers."""
        ep = self._ep(method, path)
        ep.sources.add("validated")
        ep.response_fields.update(fields)
        if status < 400 or status in (401, 403):
            ep.auth_seen.add(auth_required)

    # ---- classification -------------------------------------------------------------------------
    def classify(self, now: float | None = None) -> None:
        now = now or time.time()
        inv = self.policy["inventory"]
        current = defaultdict(int)
        for ep in self.endpoints.values():
            m = _VERSION.search(ep.path + "/")
            if m:
                base = _VERSION.sub("/v{}/", ep.path + "/", count=1)
                current[base] = max(current[base], int(m.group(1)))
        for ep in self.endpoints.values():
            self._assign_owner(ep)
            labels = []
            mapped = bool(ep.sources & {"har", "js", "crawl"})
            in_logs = "logs" in ep.sources
            recent = ep.hits_30d > 0
            m = _VERSION.search(ep.path + "/")
            older = False
            if m:
                base = _VERSION.sub("/v{}/", ep.path + "/", count=1)
                older = int(m.group(1)) < current[base]
            if in_logs and not mapped and recent:
                labels.append("shadow")
            elif mapped and recent:
                labels.append("active")
            if not recent and (older or mapped or in_logs or "validated" in ep.sources):
                if "shadow" not in labels and "active" not in labels:
                    labels.append("zombie")
            if older:
                labels.append("deprecated-live")
            if ep.owner_confidence < inv["ownership_confidence_threshold"]:
                labels.append("unowned")
            if self.high_risk(ep):
                labels.append("high-risk")
            ep.labels = labels or ["unclassified"]
            ep.recommendation, ep.reason = self._recommend(ep, older)

    def high_risk(self, ep: Endpoint) -> bool:
        names = {p.lower() for p in ep.params | ep.response_fields}
        return bool(names & MONEY_FIELDS or names & PII_FIELDS or "{" in ep.path or False in ep.auth_seen
                    or names & {"role", "agency_id", "url", "file"})

    def _assign_owner(self, ep: Endpoint) -> None:
        best = None
        for s in self.owners.get("services", []):
            if ep.path.startswith(s["prefix"]) or _VERSION.sub("/v2/", ep.path + "/", count=1).startswith(s["prefix"] + "/"):
                if not best or len(s["prefix"]) > len(best["prefix"]):
                    best = s
        if best:
            exact = ep.path.startswith(best["prefix"])
            ep.owner, ep.service = best["team"], best["service"]
            ep.owner_confidence = best["confidence"] if exact else round(best["confidence"] * 0.7, 2)
        else:
            ep.owner, ep.service, ep.owner_confidence = "Security triage queue", None, 0.2

    def _recommend(self, ep: Endpoint, older: bool) -> tuple[str | None, str | None]:
        if "zombie" in ep.labels:
            if False in ep.auth_seen:
                return "decommission", "no legitimate traffic in 30+ days and reachable without login"
            return ("decommission" if older else "restrict"), "no legitimate traffic in 30+ days"
        if "shadow" in ep.labels:
            return "bring up to date", "used in traffic but never documented or mapped; review and add to inventory"
        if "deprecated-live" in ep.labels:
            return "restrict", "older version still answering; migrate callers then retire"
        return None, None

    # ---- outputs --------------------------------------------------------------------------------
    def report(self, now: float | None = None) -> list[dict]:
        """The six required fields for every zombie or shadow endpoint (PDF §8, VERIFIED pack requirement)."""
        now = now or time.time()
        out = []
        for ep in self.endpoints.values():
            if not set(ep.labels) & {"zombie", "shadow"}:
                continue
            current = _VERSION.sub("/v2/", ep.path + "/", count=1).rstrip("/")
            exposed = sorted({f for f in ep.response_fields if f.lower() in PII_FIELDS | MONEY_FIELDS})
            out.append({
                "endpoint": ep.key, "label": [l for l in ep.labels if l in ("zombie", "shadow")][0],
                "last_real_traffic": time.strftime("%Y-%m-%d", time.gmtime(ep.last_seen)) if ep.last_seen else "never seen",
                "days_since_traffic": int((now - ep.last_seen) / DAY) if ep.last_seen else None,
                "reachable_without_auth": False in ep.auth_seen,
                "data_exposed": exposed or sorted(ep.response_fields)[:6],
                "vs_current_version": (f"compare with {ep.method} {current}" if current != ep.path else "is current version")
                + ("; current requires login, this does not" if False in ep.auth_seen else ""),
                "likely_owner": f"{ep.owner} ({ep.owner_confidence:.0%})",
                "recommendation": ep.recommendation, "reason": ep.reason,
            })
        return sorted(out, key=lambda r: (r["label"], r["endpoint"]))

    def openapi(self) -> dict:
        paths: dict = {}
        for ep in sorted(self.endpoints.values(), key=lambda e: e.key):
            op = {
                "summary": f"{ep.method} {ep.path}",
                "parameters": [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                               for n in re.findall(r"{(\w+)}", ep.path)]
                + [{"name": p, "in": "query", "schema": {"type": "string"}, "x-confidence": "inferred"}
                   for p in sorted(ep.params) if ep.method == "GET"],
                "responses": {"200": {"description": "observed", "content": {"application/json": {"schema": {
                    "type": "object", "properties": {f: {} for f in sorted(ep.response_fields)}}}}}},
                "x-owner": ep.owner, "x-status": ep.labels[0] if ep.labels else "unclassified",
                "x-labels": ep.labels, "x-sources": sorted(ep.sources),
                "x-last-seen": time.strftime("%Y-%m-%d", time.gmtime(ep.last_seen)) if ep.last_seen else None,
                "x-confidence": "observed" if "validated" in ep.sources or "har" in ep.sources else "inferred",
            }
            if ep.method != "GET" and ep.params:
                op["requestBody"] = {"content": {"application/json": {"schema": {
                    "type": "object", "properties": {p: {} for p in sorted(ep.params)}}}}}
            if True in ep.auth_seen:
                op["security"] = [{"bearer": []}]
            paths.setdefault(ep.path, {})[ep.method.lower()] = op
        return {"openapi": "3.1.0", "info": {"title": "Voyege inferred API inventory", "version": "inferred"},
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}, "paths": paths}
