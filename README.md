<h1 align="center">Voyege</h1>

<p align="center"><b>Agentic real-time security &amp; fraud shield for online booking &amp; travel platforms.</b></p>

<p align="center">
  Voyege re-checks your platform on every change, catches broken money and access rules, watches logs for
  fraud in progress, and sends a verified, ₹-ranked ticket to the right team — then retests after the fix.
  It finds the business-logic flaws that ordinary scanners structurally cannot see.
</p>

---

## Quick start

```bash
cd shield
./run.sh                                   # dashboard → http://127.0.0.1:8800
```

Open the landing page, read what Voyege is, then enter a URL for an instant **read-only** posture scan —
TLS, security headers, cookies, version disclosure, CORS, and the API routes hidden in your front-end code.
From there, **Explore the live dashboard** to see the full change → detect → verify → ticket → retest loop
running on a built-in demo platform.

```bash
cd shield
python3 -m voyege_shield.cli https://your-site.com -y   # same scan from the terminal (read-only)
python3 -m pytest -q tests                              # test suite
```

## What's inside

| Capability | Where |
|---|---|
| Safety gate (scope allowlist, rate limits, back-off, kill switch, evidence minimisation) | `shield/voyege_shield/gate.py` |
| Hash-chained flight recorder (write-before-forward) | `shield/voyege_shield/recorder.py` |
| Discovery &amp; inventory — active / zombie / shadow labels, OpenAPI 3.1 export | `shield/voyege_shield/inventory.py` |
| Change detector — signed webhook, bundle / shape / log diff, DNS/CT watch | `shield/voyege_shield/change.py` |
| Business-rule engine — the money &amp; access invariants, with controls | `shield/voyege_shield/rules.py` |
| Fraud signals in logs + "seen in traffic" | `shield/voyege_shield/fraud.py` |
| Verifier, ₹ triage, tickets, approval desk, retest | `shield/voyege_shield/triage.py` |
| Orchestrator, planner, heartbeats, safety drills | `shield/voyege_shield/orchestrator.py` |
| Read-only live URL diagnostic agent | `shield/voyege_shield/diagnose.py` |
| Dashboard + control API (FastAPI + glass UI) | `shield/voyege_shield/server.py`, `shield/voyege_shield/static/` |

See [`shield/README.md`](shield/README.md) for the full architecture map and a demo script.

## Safety

Voyege is read-only by default and runs every request through one gate: a scope allowlist, rate budgets, a
tamper-evident request log and a kill switch. The live URL diagnostic sends **no attack payloads, changes no
state and attempts no login**, and it refuses to run until you confirm you are authorised to test the target.
**Only point Voyege at systems you own or are authorised to test.**

## Scope of this prototype

The business-rule, access, fraud-log and inventory engines run end-to-end against a built-in synthetic
platform (`shield/voyege_shield/feed.py`) that stands in for the organiser-provided inputs. The live URL
feature is the read-only posture scan. Active exploitation checks (injection, auth-bypass, state-changing
tests) are intentionally not included; the safety gate already provides the enforcement those would need.
Production infrastructure (durable queue, Postgres, secret vault, proxy, ticketing) is represented by
in-process equivalents behind the same interfaces.
