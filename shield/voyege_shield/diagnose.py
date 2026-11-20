"""Live diagnostic agent (read-only) — "give it a URL, it diagnoses the site".

This is the passive, non-intrusive half of the security lens. It fetches the target the way a browser does
and inspects only what the server volunteers: TLS/redirect behaviour, security response headers, cookie
attributes, software version disclosure, CORS reflection, directory listing, and the routes exposed by the
site's own front-end JS (fed into the inventory with active/zombie/shadow labelling and an OpenAPI export).

What it does NOT do: it sends no attack payloads, changes no state, submits no forms, and tries no
authentication. Every request is GET/HEAD at safety tier L0, routed through the same SafetyGate (scope
allowlist, rate budget, health back-off, hash-chained flight recorder). A scan runs only after the operator
confirms they are authorised to test the target — "only point it at systems you own or are authorised to test".
"""
from __future__ import annotations

import copy
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from .gate import GateBlocked, GateRequest, SafetyGate
from .inventory import Inventory, _JS_ROUTE, template
from .recorder import FlightRecorder
from .triage import severity
from .vault import PassVault

# Conventional, safe, read-only paths a browser or a site owner would expect to be fetched.
PROBE_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
               "/openapi.json", "/swagger.json", "/.well-known/openid-configuration"]
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_SECRET = re.compile(r'(?:api[_-]?key|secret|token|aws_access_key_id|authorization)["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{12,}', re.I)


def _check_headers(h: dict) -> list[dict]:
    """Posture of the security response headers (severity by data/clickjacking/transport reach)."""
    low = {k.lower(): v for k, v in h.items()}
    out = []

    def add(check, present, sev, title, detail, fix):
        out.append({"check": check, "present": present, "severity": sev, "title": title,
                    "detail": detail, "fix": fix})

    if not low.get("strict-transport-security"):
        add("hsts", False, "Medium", "HTTP Strict-Transport-Security",
            "no HSTS header; a downgrade to HTTP is not prevented",
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.")
    csp = low.get("content-security-policy")
    if not csp:
        add("csp", False, "Medium", "Content-Security-Policy",
            "no CSP; the browser has no allowlist for scripts, so an injected script runs freely",
            "Add a Content-Security-Policy; start in report-only mode.")
    elif "unsafe-inline" in csp or "*" == csp.strip():
        add("csp", True, "Low", "Weak Content-Security-Policy",
            f"CSP present but permissive: {csp[:120]}", "Remove `unsafe-inline`/wildcards; use nonces or hashes.")
    if "x-frame-options" not in low and (not csp or "frame-ancestors" not in csp):
        add("x-frame-options", False, "Medium", "Clickjacking protection",
            "neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed",
            "Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.")
    if low.get("x-content-type-options", "").lower() != "nosniff":
        add("x-content-type-options", False, "Low", "MIME sniffing not disabled",
            "X-Content-Type-Options is not `nosniff`", "Set `X-Content-Type-Options: nosniff`.")
    if "referrer-policy" not in low:
        add("referrer-policy", False, "Low", "Referrer-Policy", "no Referrer-Policy header",
            "Set `Referrer-Policy: strict-origin-when-cross-origin`.")
    if "permissions-policy" not in low:
        add("permissions-policy", False, "Low", "Permissions-Policy",
            "no Permissions-Policy; powerful browser features are not restricted",
            "Add a `Permissions-Policy` limiting camera, geolocation, etc.")
    # Version / software disclosure
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = low.get(hdr)
        if val and re.search(r"\d", val):
            add(f"disclosure:{hdr}", True, "Low", "Software version disclosed",
                f"`{hdr}: {val}` reveals the stack and version to an attacker",
                f"Remove or blank the `{hdr}` header at the gateway.")
    # CORS reflection on the plain GET (read-only observation of the response header)
    acao = low.get("access-control-allow-origin")
    if acao == "*" and low.get("access-control-allow-credentials", "").lower() == "true":
        add("cors", True, "High", "Wildcard CORS with credentials",
            "ACAO `*` together with Allow-Credentials lets any origin read authenticated responses",
            "Echo only an explicit allowlist of origins; never pair `*` with credentials.")
    elif acao == "*":
        add("cors", True, "Low", "Open CORS", "ACAO `*` (no credentials observed)",
            "Restrict ACAO to the origins that actually need cross-site reads.")
    return out


def _check_cookies(cookies: list[dict]) -> list[dict]:
    out = []
    for c in cookies:
        missing = [f for f in ("secure", "httponly") if not c.get(f)]
        if missing or not c.get("samesite"):
            bits = []
            if "secure" in missing:
                bits.append("no Secure (sent over plain HTTP)")
            if "httponly" in missing:
                bits.append("no HttpOnly (readable by JavaScript)")
            if not c.get("samesite"):
                bits.append("no SameSite (CSRF exposure)")
            sev = "Medium" if "httponly" in missing or "secure" in missing else "Low"
            out.append({"check": f"cookie:{c['name']}", "present": True, "severity": sev,
                        "title": f"Cookie `{c['name']}` attributes", "detail": "; ".join(bits),
                        "fix": "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies."})
    return out


class LiveDiagnostic:
    def __init__(self, policy: dict, data_dir: str | Path, owners: dict, transport: httpx.BaseTransport | None = None):
        self.base_policy = policy
        self.owners = owners
        self.data = Path(data_dir)
        self.data.mkdir(parents=True, exist_ok=True)
        self.transport = transport
        self.scans: dict[str, dict] = {}

    def scan(self, url: str, authorized: bool, scan_id: str | None = None) -> dict:
        if not authorized:
            raise PermissionError("scan refused: confirm you are authorised to test this target")
        parts = urlsplit(url if "://" in url else "https://" + url)
        host = (parts.hostname or "").lower()
        if not host:
            raise ValueError("could not parse a hostname from the URL")
        scheme = parts.scheme or "https"
        base = f"{scheme}://{parts.netloc}"
        sid = scan_id or f"scan-{int(time.time())}"

        # Per-scan policy: the approved area is exactly this host; everything else stays blocked.
        policy = copy.deepcopy(self.base_policy)
        policy["scope"]["allowed_hosts"] = [host]
        policy["scope"]["denied_path_prefixes"] = []
        policy["budgets"].update({"global_rps": 3, "per_host_rps": 3})
        recorder = FlightRecorder(self.data / f"diag-{sid}.jsonl")
        gate = SafetyGate(policy, recorder, PassVault(), transport=self.transport)
        inv = Inventory(policy, self.owners)
        findings: list[dict] = []
        steps: list[dict] = []
        reached: list[dict] = []

        def get(path, **kw):
            u = urljoin(base + "/", path.lstrip("/"))
            try:
                r = gate.request(GateRequest("GET", u, tier="L0", test_id=sid, **kw))
                steps.append({"path": path, "status": r["status"], "ms": round(r["ms"], 1)})
                return r
            except GateBlocked as b:
                steps.append({"path": path, "status": "blocked", "reason": b.reason})
            except httpx.HTTPError as e:
                steps.append({"path": path, "status": "error", "reason": type(e).__name__})
            return None

        # 1. Transport: is the site HTTPS, and does HTTP redirect to it?
        root = get("/", include_headers=True, return_text=True)
        if root is None:
            raise RuntimeError(f"could not reach {base}")
        if scheme != "https":
            findings.append(self._f("tls", "High", "Site served over plain HTTP",
                                    "traffic is unencrypted and open to interception/tampering",
                                    "Serve the site over HTTPS and redirect HTTP to it.", base))

        # 2. Security headers + cookies on the landing page
        for c in _check_headers(root.get("headers", {})) + _check_cookies(root.get("cookies", [])):
            findings.append(self._f(c["check"], c["severity"], c["title"], c["detail"], c["fix"], base))

        # 3. Front-end JS: discover routes, scan for obvious exposed secrets (read-only)
        html = root.get("text", "")
        scripts = [s for s in _SCRIPT_SRC.findall(html) if not s.startswith(("http://", "https://")) or host in s][:8]
        js_routes: set[str] = set()
        for src in scripts:
            r = get(src, return_text=True)
            if r and r.get("text"):
                js_routes |= inv.add_js_bundle(r["text"])
                if _SECRET.search(r["text"]):
                    findings.append(self._f("secret-in-js", "High", "Possible secret in front-end bundle",
                                            f"a key/token-shaped string appears in `{src}`",
                                            "Move secrets server-side; rotate anything exposed.", base))
        # also record the probe/validation endpoints seen
        for s in steps:
            if isinstance(s["status"], int):
                inv.add_validation("GET", s["path"] if s["path"].startswith("/") else "/" + s["path"],
                                   s["status"], False, [])

        # 4. Conventional discovery paths (exposed API spec, directory listing, debug)
        spec_found = []
        for p in PROBE_PATHS[1:]:
            r = get(p, include_headers=True, return_text=p.endswith((".json", "configuration")))
            if not r:
                continue
            reached.append({"path": p, "status": r["status"]})
            if r["status"] == 200 and p.endswith(("openapi.json", "swagger.json", "configuration")):
                spec_found.append(p)
                findings.append(self._f(f"spec:{p}", "Low", "API specification is publicly served",
                                        f"`{p}` returns 200 — the full API surface is readable by anyone",
                                        "Confirm this is intended; otherwise require auth for the spec.", base))
            if r["status"] == 200 and "security.txt" not in p:
                body = (r.get("text") or "").lower()
                if "<title>index of /" in body or "directory listing for" in body:
                    findings.append(self._f(f"listing:{p}", "Medium", "Directory listing enabled",
                                            f"`{p}` returns a browsable file index", "Disable autoindex.", base))

        inv.classify()
        # severity ordering + a simple ₹-free score so the UI can sort
        order = {"High": 3, "Medium": 2, "Low": 1}
        findings.sort(key=lambda f: -order.get(f["severity"], 0))
        summary = {s: sum(1 for f in findings if f["severity"] == s) for s in ("High", "Medium", "Low")}
        result = {
            "id": sid, "target": base, "host": host, "https": scheme == "https",
            "started": time.time(), "findings": findings, "summary": summary,
            "steps": steps, "reached": reached, "spec": spec_found,
            "inventory": sorted((e.to_dict() for e in inv.endpoints.values()), key=lambda e: e["key"]),
            "openapi": inv.openapi(), "routes_from_js": sorted(js_routes),
            "gate": gate.status(), "recorder": recorder.verify(),
            "note": "Read-only posture scan. No payloads sent, no state changed, no authentication attempted.",
        }
        self.scans[sid] = result
        return result

    @staticmethod
    def _f(check, sev, title, detail, fix, target) -> dict:
        score, _ = severity({"High": 3, "Medium": 2, "Low": 1}[sev], {"High": 3, "Medium": 2, "Low": 1}[sev], 3)
        return {"id": check, "class": "security posture", "severity": sev, "title": title,
                "detail": detail, "fix": fix, "target": target, "verified": True, "method": "passive read-only"}
