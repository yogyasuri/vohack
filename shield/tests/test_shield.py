"""Proof plan checks (PDF Part A §15, Part B §4F part 3: "what would prove us wrong")."""
import json

import httpx
import pytest
import yaml

from voyege_shield import rules as R
from voyege_shield.change import ChangeDetector, sign
from voyege_shield.gate import GateBlocked, GateRequest, SafetyGate
from voyege_shield.inventory import Inventory, template
from voyege_shield.orchestrator import ROOT, Orchestrator
from voyege_shield.recorder import FlightRecorder
from voyege_shield.triage import severity
from voyege_shield.vault import PassVault

POLICY = yaml.safe_load((ROOT / "config/policy.yaml").read_text())
CATALOGUE = {r["id"]: r for r in yaml.safe_load((ROOT / "config/invariants.yaml").read_text())["rules"]}


@pytest.fixture
def gate(tmp_path):
    rec = FlightRecorder(tmp_path / "f.jsonl")
    g = SafetyGate(POLICY, rec, PassVault(), httpx.MockTransport(lambda r: httpx.Response(200, json={"id": 1, "a": 2})))
    return g, rec


def test_recorder_chain_detects_tampering(tmp_path):
    rec = FlightRecorder(tmp_path / "f.jsonl")
    for i in range(5):
        rec.append("request", {"i": i})
    assert rec.verify()["ok"]
    lines = (tmp_path / "f.jsonl").read_text().splitlines()
    doc = json.loads(lines[2]); doc["data"]["i"] = 99
    lines[2] = json.dumps(doc)
    (tmp_path / "f.jsonl").write_text("\n".join(lines) + "\n")
    assert rec.verify() == {"ok": False, "records": 5, "broken_at": 2}


def test_gate_blocks_out_of_scope_and_denied_paths(gate):
    g, _ = gate
    for url in ("http://169.254.169.254/", "https://evil.example/x", "https://api.staging.tbo.test/__control/deploy"):
        with pytest.raises(GateBlocked) as e:
            g.request(GateRequest("GET", url))
        assert e.value.check == "1-scope"
    assert g.counters["forwarded"] == 0


def test_gate_refuses_when_recorder_down(gate):
    g, rec = gate
    rec.available = False
    with pytest.raises(GateBlocked) as e:
        g.request(GateRequest("GET", "https://api.staging.tbo.test/api/v2/wallet"))
    assert e.value.check == "6-recorder" and g.counters["forwarded"] == 0


def test_gate_kill_switch_and_write_rules(gate):
    g, _ = gate
    url = "https://api.staging.tbo.test/api/v2/bookings"
    with pytest.raises(GateBlocked, match="synthetic"):
        g.request(GateRequest("POST", url, tier="L2", json_body={"x": "real"}, cleanup_registered=True))
    with pytest.raises(GateBlocked, match="undo"):
        g.request(GateRequest("POST", url, tier="L2", json_body={"x": "VOYEGE-SYNTH"}))
    with pytest.raises(GateBlocked, match="approval"):
        g.request(GateRequest("POST", url, tier="L3", json_body={"x": "VOYEGE-SYNTH"}, cleanup_registered=True, concurrency=True))
    assert g.request(GateRequest("POST", url, tier="L2", json_body={"x": "VOYEGE-SYNTH"}, cleanup_registered=True))["status"] == 200
    g.kill()
    with pytest.raises(GateBlocked, match="kill"):
        g.request(GateRequest("GET", url))


def test_vault_never_exposes_tokens():
    v = PassVault()
    h = v.register("A", "agent", "secret-token")
    assert "secret-token" not in json.dumps(v.handles())


def test_template_normalisation():
    assert template("/api/v2/bookings/8812/refunds") == "/api/v2/bookings/{bookingId}/refunds"
    assert template("/api/v2/invoices/550e8400-e29b-41d4-a716-446655440000") == "/api/v2/invoices/{invoiceId}"


def test_labels_zombie_and_shadow():
    o = Orchestrator.__new__(Orchestrator)
    inv = Inventory(POLICY, yaml.safe_load((ROOT / "config/owners.yaml").read_text()))
    import time
    now = time.time()
    inv.add_js_bundle('api.get("/api/v2/bookings/${id}")')
    rows = [{"ts": now - 2 * 86400, "method": "GET", "path": "/api/v2/bookings/1", "auth": True},
            {"ts": now - 75 * 86400, "method": "GET", "path": "/api/v1/bookings/1", "auth": False},
            {"ts": now - 86400, "method": "GET", "path": "/api/v2/partner/availability", "auth": True},
            {"ts": now - 60, "method": "GET", "path": "/api/v1/bookings/2", "auth": False, "account": "vtest-x"}]
    inv.add_gateway_logs(rows, now)
    inv.classify(now)
    e = inv.endpoints
    assert "active" in e["GET /api/v2/bookings/{bookingId}"].labels
    assert "zombie" in e["GET /api/v1/bookings/{bookingId}"].labels  # own test traffic ignored
    assert "shadow" in e["GET /api/v2/partner/availability"].labels
    rep = {r["endpoint"]: r for r in inv.report(now)}
    z = rep["GET /api/v1/bookings/{bookingId}"]
    assert z["reachable_without_auth"] and z["recommendation"] == "decommission"
    assert set(z) >= {"last_real_traffic", "reachable_without_auth", "data_exposed", "vs_current_version", "likely_owner", "recommendation"}
    assert inv.openapi()["openapi"] == "3.1.0"


def test_every_rule_has_a_passing_control_and_flags_a_break():
    for rid, rule in CATALOGUE.items():
        assert R.control_holds(rule), rid
    snap = R.empty_snapshot()
    snap["bookings"] = [{"id": "B1", "agency": "A", "quote_id": "Q1", "charged": 500, "status": "confirmed", "ts": 1}]
    snap["quotes"] = [{"id": "Q1", "agency": "A", "total": 1000, "nights": 1, "guests": 1, "ts": 1}]
    snap["payments"] = [{"booking_id": "B1", "amount": 500, "status": "captured", "instrument": "card", "ts": 1}]
    snap["refunds"] = [{"id": "R1", "booking_id": "B1", "amount": 400, "destination": "card", "ts": 2},
                       {"id": "R2", "booking_id": "B1", "amount": 400, "destination": "elsewhere", "ts": 3}]
    hit = {rid for rid, rule in CATALOGUE.items() if R.run(rule, snap)}
    assert {"INV-M1", "INV-M2", "INV-M7", "INV-M3"} <= hit
    assert not R.run(CATALOGUE["INV-M4"], snap)  # paid booking is a negative control


def test_severity_formula_matches_report():
    assert severity(3, 4, 3) == (36, "Critical")   # FR-14 worked example
    assert severity(2, 3, 2) == (12, "High")       # SEC-10 worked example
    assert severity(1, 2, 3)[1] == "Medium" and severity(1, 1, 2)[1] == "Low"


def test_webhook_signature_and_dedupe():
    d = ChangeDetector(POLICY, "s3cret", POLICY["scope"]["allowed_hosts"])
    body = b'{"service":"refunds-svc"}'
    with pytest.raises(PermissionError):
        d.webhook(body, "sha256=bad", {"service": "refunds-svc"})
    assert d.webhook(body, sign("s3cret", body), {"service": "refunds-svc"})
    assert d.webhook(body, sign("s3cret", body), {"service": "refunds-svc"}) is None


def test_full_loop_deploy_detect_fix_retest(tmp_path):
    o = Orchestrator(data_dir=tmp_path)
    o.cold_start()
    initial = {f["rule_id"] for f in o.desk.findings.values()}
    assert {"INV-M4", "INV-C1"} <= initial and "INV-M2" not in initial
    for rel in ("r2.5.0", "r2.5.1"):
        d = o.simulate_deploy(rel)
        assert o.receive_webhook(d["body"], d["signature"])["accepted"]
        o.handle(o.events.get_nowait())
    refund = next(f for f in o.desk.findings.values() if f["rule_id"] == "INV-M2")
    assert refund["severity"] == "Critical" and refund["status"] == "closed"
    assert refund["owner"] in ("Booking", "Refunds")
    assert o.recorder.verify()["ok"]
    assert o.gate.counters["out_of_scope"] == 0
