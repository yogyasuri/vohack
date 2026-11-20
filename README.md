<h1 align="center">Voyege</h1>
<p align="center"><b>Agentic real-time security &amp; fraud shield for B2B travel platforms</b></p>
<p align="center">
  <i>TBO Security Hackathon 2026 · Agentic Real-Time DAST</i><br>
  Built by <b>Yogya Suri</b>
</p>

---

## Why I built this

TBO's real exposure isn't "unscanned endpoints." It's that every deploy can quietly break a rule that moves
money or guards a tenant — *who may see a booking, what a refund may be, how often a coupon works* — and no
conventional control checks those rules against the live app within minutes. A generic scanner judges HTTP
responses; it has no idea that `refund_amount > paid_amount` is a loss, or that Agency A just read Agency B's
booking.

**Voyege** is my answer to the brief: a hybrid, invariant-driven DAST and fraud shield. Deterministic engines
do the testing; AI is used only to plan and to draft reports. Every request to the target passes through one
safety gate the agents cannot bypass. It re-checks the platform on every change, proves each finding twice,
prices it in ₹ at risk, tickets the right owner, and retests after the fix.

> The analogy I keep coming back to: TBO is a large airport. New gates open every day (new APIs). Some old
> doors are forgotten but still unlocked (zombie / shadow APIs). And most losses come not from break-ins but
> from people misusing valid passes — walking into another airline's office, or getting refunded twice.
> Voyege is the security team that watches all three.

## What makes it win on the judging weights

| Criterion (weight) | What carries it in Voyege |
|---|---|
| **Valid findings & severity (30%)** | An invariant engine that finds the business-logic flaws scanners miss, scored by ₹ at risk |
| **Precision (20%)** | Every finding re-proved by an independent verifier with a control request — the AI can never mark "verified" |
| **Safety (20%)** | One scope gate: allowlist, budgets, health back-off, kill switch, and a hash-chained replayable log |
| **Speed (10%)** | Change-driven: deploy webhook + JS-bundle diff + response-shape drift → change-scoped tests |
| **Report quality (10%)** | Ticket-ready JSON/markdown with owner, reproduction, fix and auto-retest |
| **Discovery (10%)** | Multi-source crawl → API graph with active / zombie / shadow labels and an OpenAPI 3.1 export |

## Run it

```bash
cd shield
./run.sh                                   # dashboard → http://127.0.0.1:8800
```

The landing page explains what Voyege is, then lets you **enter any URL for an instant read-only posture
scan** (TLS, security headers, cookies, version disclosure, CORS, and the API routes hidden in the site's
front-end JS). From there, **Explore the live dashboard** to watch the full loop run on a built-in demo
platform: ship a deploy, catch a planted money-rule break, confirm the ticket, deploy the fix, and see the
ticket auto-close — plus safety drills (out-of-scope blocked, latency back-off, log-outage refusal, kill
switch) and the tamper-evident flight recorder.

```bash
python3 -m voyege_shield.cli https://your-site.com -y   # same read-only scan from the terminal
python3 -m pytest -q tests                              # 11 proof-plan tests
```

## The 11 live rules (my invariant catalogue)

The core differentiator from the report — machine-checkable rules over *persisted state*, each tested by
reading the saved record back, not by trusting a response:

| ID | Rule | Safety tier |
|---|---|---|
| INV-M1 | Amount charged = the server's quoted price | L2 |
| INV-M10 | Markup / commission change only by authorised roles, within range | L2 |
| INV-M2 | Refunds for a booking never exceed the eligible amount paid | L3 |
| INV-M7 | One refund per cancellation, even under concurrency | L3 |
| INV-M3 | Refund goes only to the original instrument or agency wallet | L3 |
| INV-M4 | No confirmation / ticket without captured payment or reserved credit | L2 |
| INV-C1 | Coupon redemptions never exceed the allowed count | L2 |
| INV-M8 | Quantities and amounts are never negative or zero-priced | L2 |
| INV-M5 | Agency spend never exceeds its credit limit, even under concurrency | L3 |
| INV-S2 | Holds are capped per agency and expire on time | L2 |
| INV-R1 | Payment, booking and supplier records reconcile | L0 |

Safety tiers: **L0** look only · **L1** read with altered inputs · **L2** make a test change and undo it ·
**L3** touches money (synthetic data, standing approval within budget, human sign-off for concurrency).

## Architecture

Thirteen parts in one loop; only the safety gate ever touches the platform under test. Deterministic by
default, AI at three points (plan hypotheses, map learned flows to the generic models, draft report prose).

| Part | File |
|---|---|
| Safety gate — 7 checks, scope allowlist, budgets, back-off, kill switch, evidence minimisation | `shield/voyege_shield/gate.py` |
| Flight recorder — append-only, hash-chained, write-before-forward | `shield/voyege_shield/recorder.py` |
| Pass vault — session handles, never raw credentials | `shield/voyege_shield/vault.py` |
| Discovery & inventory — crawl/HAR/JS/logs → graph, zombie/shadow labels, OpenAPI 3.1 | `shield/voyege_shield/inventory.py` |
| Change detector — signed webhook, bundle / shape / log diff, DNS-CT watch | `shield/voyege_shield/change.py` |
| Business-rule engine — the 11 invariants, with controls | `shield/voyege_shield/rules.py` |
| Fraud signals in logs — "seen in traffic" on the ticket | `shield/voyege_shield/fraud.py` |
| Verifier · ₹ triage · tickets · approval desk · retest | `shield/voyege_shield/triage.py` |
| Orchestrator · deterministic planner · heartbeats · safety drills | `shield/voyege_shield/orchestrator.py` |
| Read-only live URL diagnostic agent | `shield/voyege_shield/diagnose.py` |
| Dashboard + control API | `shield/voyege_shield/server.py`, `shield/voyege_shield/static/` |

Full architecture map and demo script: [`shield/README.md`](shield/README.md).

## Severity model

`Score = Exploitability (0–3) × Impact (0–4) × Reach (1–3)` → Critical ≥ 24, High 12–23, Medium 6–11,
Low < 6, with a ₹-at-risk estimate attached. Worked example — coupon reuse: `3 × 4 × 3 = 36 → Critical`,
₹ at risk = coupon value × expected redemptions. A generic scanner would not report it at all.

## Safety — by design, not by policy

Read-only by default. Agents have no network path to the target except the gate, which enforces scope, rate
budgets and health back-off, logs every request to a hash-chained recorder *before* forwarding, and refuses
to forward anything it cannot log. The live URL diagnostic sends **no attack payloads, changes no state and
attempts no login**, and refuses to run until you confirm authorisation. **Only point Voyege at systems you
own or are authorised to test.**

## Honest scope

- The business-rule, access, fraud-log and inventory engines run end-to-end against a built-in synthetic
  platform (`shield/voyege_shield/feed.py`) that stands in for the organiser-provided inputs (HAR, bundle,
  90 days of gateway logs, DNS, a records export). Point the feed at real exports to use it for real.
- The live URL feature is the read-only posture scan. Active exploitation executors (injection, auth-bypass,
  state-changing tests) are intentionally **not** included; the gate already provides the enforcement they'd
  need, behind the same interfaces.
- Scores and timings from the report are targets/projections, to be measured on the benchmark — not claims.

---

<p align="center"><sub>Voyege · Yogya Suri · TBO Security Hackathon 2026</sub></p>
