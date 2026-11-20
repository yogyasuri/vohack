"""Voyege dashboard + control API (PDF Part B §4A outputs: dashboard, approval desk, kill switch, OpenAPI)."""
from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from .orchestrator import Orchestrator
from .triage import FindingDesk

STATIC = Path(__file__).parent / "static"
orch = Orchestrator()
_started = threading.Event()


@asynccontextmanager
async def lifespan(_app):
    def run():
        orch.start()  # cold start (discovery + full sweep) runs off the request path
        _started.set()
    threading.Thread(target=run, daemon=True).start()
    yield


app = FastAPI(title="Voyege Security & Fraud Shield", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/state")
def state():
    if not _started.is_set():
        return {"booting": True, "timeline": orch.timeline[::-1]}
    return JSONResponse(orch.state())


@app.post("/webhook/deploy")
async def webhook(request: Request):
    body = await request.body()
    try:
        return orch.receive_webhook(body, request.headers.get("X-Voyege-Signature", ""))
    except PermissionError as exc:
        raise HTTPException(401, str(exc))


@app.post("/api/simulate/deploy/{release}")
def simulate_deploy(release: str):
    """Organiser side: ship a release on the synthetic platform; it sends a signed webhook to us."""
    try:
        d = orch.simulate_deploy(release)
    except KeyError:
        raise HTTPException(404, "unknown release")
    return {**orch.receive_webhook(d["body"], d["signature"]), "release": release}


@app.post("/api/simulate/dns/{host}")
def simulate_dns(host: str):
    return {"events": orch.add_host(host)}


@app.post("/api/findings/{fid}/{decision}")
def decide(fid: str, decision: str, request: Request):
    if decision not in ("approve", "reject"):
        raise HTTPException(400, "approve or reject")
    try:
        return orch.desk.approve(fid, request.headers.get("X-Reviewer", "security-lead"), decision)
    except KeyError:
        raise HTTPException(404, "unknown finding")


@app.get("/api/tickets/{fid}.md", response_class=PlainTextResponse)
def ticket(fid: str):
    try:
        return FindingDesk.markdown(orch.desk._by_id(fid))
    except KeyError:
        raise HTTPException(404, "unknown finding")


@app.post("/api/approvals/batch")
def batch(purpose: str = "concurrency batch", who: str = "security-lead"):
    return orch.desk.grant_batch(purpose, who)


@app.post("/api/kill")
def kill():
    orch.gate.kill("dashboard")
    return orch.gate.status()


@app.post("/api/resume")
def resume():
    orch.resume()
    return orch.gate.status()


@app.post("/api/drill/{name}")
def drill(name: str):
    try:
        return orch.drill(name)
    except KeyError:
        raise HTTPException(404, "unknown drill")


@app.post("/api/diagnose")
async def diagnose(request: Request):
    """Read-only posture scan of a user-supplied URL. Requires an explicit authorisation acknowledgement."""
    body = await request.json()
    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(400, "provide a url")
    if not body.get("authorized"):
        raise HTTPException(403, "confirm you are authorised to test this target")
    try:
        res = await run_in_threadpool(orch.diagnostic.scan, url, True)
    except (PermissionError, ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc))
    orch._t("diagnose", f"read-only scan of {res['host']}: "
            f"{res['summary']['High']}H/{res['summary']['Medium']}M/{res['summary']['Low']}L, "
            f"{len(res['inventory'])} routes")
    return res


@app.get("/api/diagnose/{sid}/openapi.json")
def diagnose_openapi(sid: str):
    scan = orch.diagnostic.scans.get(sid)
    if not scan:
        raise HTTPException(404, "unknown scan")
    return scan["openapi"]


@app.get("/api/openapi.json")
def openapi():
    return orch.inventory.openapi()


@app.get("/api/recorder")
def recorder(limit: int = 60):
    return {"verify": orch.recorder.verify(), "records": orch.recorder.records()[-limit:][::-1]}


def main() -> None:
    import argparse

    import uvicorn
    ap = argparse.ArgumentParser(description="Voyege Security & Fraud Shield dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8800)
    a = ap.parse_args()
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
