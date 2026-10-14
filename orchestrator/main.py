"""CyberShield orchestrator: the single process that closes the loop.

Wazuh pushes alerts here (webhook) -> incidents are grouped and debounced ->
the agent investigates -> the policy table recommends -> the analyst decides ->
approved actions go back to Wazuh Active Response. Every step is audited.
"""
import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from agent_worker import check_citations, run_agent
from audit import AuditLog
from incidents import IncidentManager, State
from normalise import Event, normalise
from policy import ACTION_SCRIPTS, AUTOMATIC, apply_floors, recommend
from wazuh import Indexer, Server

log = logging.getLogger("cybershield")
ENV = os.environ
for required in ("INGEST_TOKEN", "ANALYST_USER", "ANALYST_PASS"):
    if not ENV.get(required):
        raise SystemExit(f"set {required} before starting the orchestrator")

CA = ENV.get("WAZUH_CA") or False  # lab only: point this at the Wazuh CA file to verify TLS
audit = AuditLog(ENV.get("AUDIT_PATH", "audit.jsonl"))
indexer = (Indexer(ENV["INDEXER_URL"], ENV["INDEXER_USER"], ENV["INDEXER_PASS"], CA)
           if ENV.get("INDEXER_URL") else None)
server = Server(ENV.get("WAZUH_API_URL"), ENV.get("WAZUH_AR_USER"), ENV.get("WAZUH_AR_PASS"), CA,
                dry_run=ENV.get("DRY_RUN") == "1")
sockets: set[WebSocket] = set()


async def broadcast(msg):
    for ws in list(sockets):
        try:
            await ws.send_json(msg)
        except Exception:
            sockets.discard(ws)


async def investigate(iid):
    """Called by the state machine when debouncing ends or new evidence arrives."""
    try:
        events = [Event(**e) for e in incidents.events(iid)]
        audit.append("investigation_started", incident=iid, alerts=[e.alert_id for e in events])
        verdict = check_citations(await run_agent(events), events)
        conf, stage = apply_floors(verdict.confidence, verdict.stage, events)
        action = recommend(conf, stage)  # TODO: critical-asset flag from an asset list
        incidents.set_verdict(iid, verdict, conf, stage, action)
        audit.append("verdict", incident=iid, confidence=conf, stage=stage, action=action,
                     cited=[c["alert_id"] for c in verdict.claims])
        incidents.complete(iid, State.MONITORING if action in AUTOMATIC else State.AWAITING_DECISION)
        await broadcast({"type": "incident", "id": iid})
    except Exception as exc:  # a failed investigation must not take the service down
        log.exception("investigation failed for %s", iid)
        audit.append("investigation_failed", incident=iid, error=str(exc))


incidents = IncidentManager(
    ENV.get("DB_PATH", "cybershield.db"), audit, on_ready=investigate,
    quiet_s=float(ENV.get("DEBOUNCE_QUIET_S", 30)), max_wait_s=float(ENV.get("DEBOUNCE_MAX_S", 300)))


async def catch_up():
    """Push can miss alerts (orchestrator down); search the indexer every minute."""
    while True:
        await asyncio.sleep(60)
        try:
            for a in await indexer.alerts_since(incidents.last_seen_ts()):
                ev = normalise(a)
                if ev.src_ip:
                    incidents.attach(ev)  # duplicates are ignored by alert ID
        except Exception:
            log.exception("catch-up search failed")


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(catch_up()) if indexer else None
    if not indexer:
        log.warning("INDEXER_URL not set: catch-up search disabled (push only)")
    yield
    if task:
        task.cancel()


# Every endpoint is async: SQLite is only touched from the event-loop thread.
app = FastAPI(title="CyberShield orchestrator", lifespan=lifespan)
basic = HTTPBasic()


def analyst(cred: HTTPBasicCredentials = Depends(basic)):
    ok = hmac.compare_digest(cred.username, ENV["ANALYST_USER"]) and \
        hmac.compare_digest(cred.password, ENV["ANALYST_PASS"])
    if not ok:
        raise HTTPException(401)
    return cred.username


@app.post("/ingest/wazuh")
async def ingest(alert: dict, x_cybershield_token: str = Header(...)):
    if not hmac.compare_digest(x_cybershield_token, ENV["INGEST_TOKEN"]):
        raise HTTPException(401)
    ev = normalise(alert)
    if ev.src_ip is None:
        return {"ignored": "no source address"}  # TODO: Stage 2 session linking
    return {"incident": incidents.attach(ev)}


@app.get("/incidents")
async def list_incidents():
    return incidents.list()


@app.get("/incidents/{iid}")
async def get_incident(iid: str):
    try:
        return incidents.get(iid) | {"events": incidents.events(iid)}
    except KeyError:
        raise HTTPException(404)


class Decision(BaseModel):
    approve: bool
    note: str = ""


@app.post("/incidents/{iid}/decision")
async def decide(iid: str, d: Decision, who: str = Depends(analyst)):
    try:
        inc = incidents.get(iid)
    except KeyError:
        raise HTTPException(404)
    if inc["state"] not in (State.AWAITING_DECISION.value, State.OVERDUE.value):
        raise HTTPException(409, f"incident is {inc['state']}, not waiting for a decision")
    audit.append("decision", incident=iid, analyst=who, approve=d.approve, note=d.note)
    if not d.approve:
        incidents.transition(iid, State.MONITORING, reason=f"rejected by {who}")
        return {"state": State.MONITORING.value}
    incidents.transition(iid, State.RESPONDING, reason=f"approved by {who}")
    script = ACTION_SCRIPTS[inc["action"]]  # fixed mapping, never the AI's text
    result = await server.run_ar(inc["agent_id"], script, inc["src_ip"])
    audit.append("action", incident=iid, script=script, result=result)
    incidents.transition(iid, State.MONITORING, reason="action confirmed")
    await broadcast({"type": "incident", "id": iid})
    return {"state": State.MONITORING.value, "script": script, "result": result}


@app.get("/audit/verify")
async def verify():
    return audit.verify()


@app.get("/health")
async def health():
    return {"ok": True, "catch_up": indexer is not None, "dry_run": server.dry_run}


@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    sockets.add(sock)
    try:
        while True:
            await sock.receive_text()
    finally:
        sockets.discard(sock)
