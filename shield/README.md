# Voyege Security & Fraud Shield

The custom travel core from *TBO Security & Fraud Shield: Integrated Report* (Part B), built on the
0security foundation in this repository. It re-checks the travel platform after every change and catches
broken money and access rules. It watches logs for fraud already in progress, proves each finding twice and
ranks it in ₹. It then holds Critical/High tickets for a person, sends the ticket to the owning team, and
closes it only when a retest passes.

```bash
./run.sh                                      # dashboard on http://127.0.0.1:8800
python3 -m pytest -q tests                    # proof-plan checks (PDF §15 / §4F part 3)
python3 -m voyege_shield.cli <url> -y         # diagnose a live site, read-only (terminal)
```

## Diagnose a URL (read-only live agent)

Give it a web URL and it diagnoses the site. On the dashboard use the **Diagnose a URL** tab (tick the
authorisation box); from the terminal use the CLI above; over HTTP, `POST /api/diagnose {"url","authorized":true}`.

It fetches the target the way a browser does and reports on what the server volunteers:

* HTTPS / HTTP-redirect, HSTS, Content-Security-Policy, clickjacking, MIME-sniffing, Referrer- and
  Permissions-Policy
* cookie `Secure` / `HttpOnly` / `SameSite` attributes (cookie *values* are never stored)
* software/version disclosure (`Server`, `X-Powered-By`, …) and wildcard-CORS-with-credentials
* routes exposed by the site's own front-end JS → inventory with active/zombie/shadow labels + OpenAPI 3.1
* conventional discovery paths (`robots.txt`, `openapi.json`, directory listing, `security.txt`)

It is **passive**: GET/HEAD only, safety tier L0, every request through the same `SafetyGate` (per-scan scope
allowlist = just that host, rate budget, hash-chained flight recorder). It sends **no attack payloads, changes
no state, and attempts no authentication**, and it refuses to run until you confirm you are authorised to test
the target. Active exploitation checks are intentionally **not** included (see below).

## Demo script (≈ 5 minutes, mirrors PDF §21)

1. **Inventory**: *API inventory* tab shows the endpoint graph and the zombie (`/api/v1/bookings/{id}`,
   no login, 85 days quiet → decommission) and shadow (`/api/v2/partner/availability`) endpoints with the
   six required fields. *Download OpenAPI 3.1* exports the graph.
2. **Deploy**: *Ship r2.5.0* sends a signed webhook. The *Live timeline* shows the deploy, bundle diff,
   traffic diff, the planner's targeted checks and a verified **Critical INV-M2** refund finding.
3. **Ticket**: the finding shows owner, `3 × 4 × 2` score, ₹ observed and at risk, *Seen in traffic: yes*,
   reproduction and fix. *Confirm & send ticket* is the human gate for Critical/High.
4. **Fix**: *Ship r2.5.1*. The retest re-runs the rule on post-deploy records and closes the ticket.
5. **Safety**: run the drills. *Out-of-scope* is blocked and three blocks pause the planner. *Latency spike*
   halves the rate. *Log outage* refuses to forward. *Unsafe write* blocks non-synthetic data, a missing undo
   and an unapproved L3 batch. The *Kill switch* drops all traffic. *Flight recorder* shows the verified hash
   chain.

## Map to the report

| PDF component | Module |
|---|---|
| Policy store, rule catalogue, ownership data | `config/policy.yaml`, `config/invariants.yaml`, `config/owners.yaml` |
| Safety gate: 7 checks, budgets, back-off, kill switch, evidence minimisation | `voyege_shield/gate.py` |
| Flight recorder: hash-chained, write-before-forward | `voyege_shield/recorder.py` |
| Pass vault: handles, never credentials | `voyege_shield/vault.py` |
| Discovery & inventory: HAR, JS bundle, gateway logs, validation, labels, six fields, OpenAPI 3.1 | `voyege_shield/inventory.py` |
| Change detector: signed webhook + dedupe, bundle diff, shape drift, log diff, DNS/CT (report only) | `voyege_shield/change.py` |
| Business-rule engine: the 11 live rules with controls (§4D) | `voyege_shield/rules.py` |
| Fraud signals in logs + "Seen in traffic" (§2A) | `voyege_shield/fraud.py` |
| Verifier, ₹ triage (E × I × R), dedupe, tickets, approval desk, retest | `voyege_shield/triage.py` |
| Orchestrator, deterministic planner, heartbeats, safety drills | `voyege_shield/orchestrator.py` |
| Dashboard + control API | `voyege_shield/server.py`, `voyege_shield/static/index.html` |

Tickets are written as Jira/GitHub-issue JSON and markdown to `data/tickets/`. The flight recorder log is
`data/flight-*.jsonl`.

## What this prototype does not include

* **Live attack executors.** The access replay, injection, server-side, identity and API-hygiene executors
  that send test traffic to the platform are not part of this prototype. The gate already enforces every rule
  those executors would need. Add them as workers that call `SafetyGate.request` only.
* **Platform data.** Records and logs come from `feed.py`, a synthetic stand-in for the organisers' inputs
  (HAR, bundle, 90 days of gateway logs, DNS, records export). Releases change how new records are written,
  so the deploy → detect → fix → retest loop is demonstrable. Point the feed at real exports to use it for
  real.
* **Production infrastructure.** The PDF's production stack (Redis Streams/Temporal, PostgreSQL,
  HashiCorp Vault, mitmproxy/Envoy, Jira) is replaced by in-process equivalents behind the same interfaces.
* **Measured numbers.** All scores and timings in the report are targets, not measured results.
