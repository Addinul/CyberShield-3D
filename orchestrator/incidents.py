"""Group alerts into incidents and decide when the AI runs.

Containment never waits for this: Wazuh redirects or isolates on its own.
Debouncing only decides when the AI is called.
"""
import asyncio
import enum
import json
import sqlite3
import time
import uuid


class State(str, enum.Enum):
    COLLECTING = "collecting"
    INVESTIGATING = "investigating"
    AWAITING_DECISION = "awaiting_decision"
    OVERDUE = "overdue"
    RESPONDING = "responding"
    MONITORING = "monitoring"
    CLOSED = "closed"


TRANSITIONS = {
    State.COLLECTING: {State.INVESTIGATING},
    State.INVESTIGATING: {State.AWAITING_DECISION, State.MONITORING},
    State.AWAITING_DECISION: {State.RESPONDING, State.MONITORING, State.INVESTIGATING, State.OVERDUE},
    State.OVERDUE: {State.RESPONDING, State.MONITORING},
    State.RESPONDING: {State.MONITORING, State.AWAITING_DECISION},
    State.MONITORING: {State.INVESTIGATING, State.CLOSED},
    State.CLOSED: set(),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, key TEXT, state TEXT, agent_id TEXT, src_ip TEXT,
  opened_at REAL, last_event_at REAL, runs INTEGER DEFAULT 0, dirty INTEGER DEFAULT 0,
  confidence TEXT, stage TEXT, action TEXT, verdict TEXT);
CREATE TABLE IF NOT EXISTS events (
  alert_id TEXT PRIMARY KEY, incident_id TEXT, ts TEXT, body TEXT);
"""


class IncidentManager:
    """Not thread-safe: call it only from the asyncio event-loop thread."""

    def __init__(self, db_path, audit, on_ready, quiet_s=30, max_wait_s=300, window_s=1800, max_runs=3):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.audit, self.on_ready = audit, on_ready
        self.quiet_s, self.max_wait_s, self.window_s, self.max_runs = quiet_s, max_wait_s, window_s, max_runs
        self.timers: dict[str, asyncio.TimerHandle] = {}

    def attach(self, ev) -> str | None:
        """Add an event to its live incident (or open one). None means a duplicate."""
        if self.db.execute("SELECT 1 FROM events WHERE alert_id=?", (ev.alert_id,)).fetchone():
            return None  # already seen via push or catch-up
        key = f"{ev.src_ip}|{ev.agent_id}"  # TODO: auditd session link for Stage 2 alerts with no IP
        iid, state = self._live_incident(key, ev)
        self.db.execute("INSERT INTO events VALUES (?,?,?,?)",
                        (ev.alert_id, iid, ev.ts, json.dumps(ev.__dict__)))
        self.db.execute("UPDATE incidents SET last_event_at=? WHERE id=?", (time.time(), iid))
        self.db.commit()
        if state == State.COLLECTING:
            self._debounce(iid, urgent=ev.urgent)
        elif state == State.INVESTIGATING:
            self._set(iid, dirty=1)  # the running investigation missed this; re-run when it ends
        elif state in (State.AWAITING_DECISION, State.MONITORING):
            self._rerun(iid)  # new evidence: investigate again, within the call cap
        return iid

    def transition(self, iid, new: State, reason=""):
        old = State(self._row(iid)["state"])
        if new not in TRANSITIONS[old]:
            raise ValueError(f"illegal transition {old.value} -> {new.value}")
        self._set(iid, state=new.value)
        self.audit.append("transition", incident=iid, old=old.value, new=new.value, reason=reason)

    def complete(self, iid, new: State):
        """End an investigation; re-run at once if evidence arrived while it ran."""
        self.transition(iid, new, reason="investigation finished")
        if self._row(iid)["dirty"]:
            self._set(iid, dirty=0)
            self._rerun(iid)

    def set_verdict(self, iid, verdict, confidence, stage, action):
        self._set(iid, confidence=confidence, stage=stage, action=action,
                  verdict=json.dumps(verdict.__dict__))

    def get(self, iid) -> dict:
        row = self._row(iid)
        if row is None:
            raise KeyError(iid)
        inc = dict(row)
        inc["verdict"] = json.loads(inc["verdict"]) if inc["verdict"] else None
        return inc

    def events(self, iid) -> list[dict]:
        rows = self.db.execute("SELECT body FROM events WHERE incident_id=? ORDER BY ts", (iid,))
        return [json.loads(r["body"]) for r in rows]

    def list(self) -> list[dict]:
        rows = self.db.execute("SELECT id, state, src_ip, agent_id, confidence, stage, action, runs"
                               " FROM incidents ORDER BY opened_at DESC")
        return [dict(r) for r in rows]

    def last_seen_ts(self) -> str | None:
        row = self.db.execute("SELECT MAX(ts) AS ts FROM events").fetchone()
        return row["ts"]

    # TODO: hold-while-pending loop (extend containment, AWAITING_DECISION -> OVERDUE at the cap)
    # TODO: close incidents after `window_s` of quiet in MONITORING

    def _live_incident(self, key, ev):
        row = self.db.execute(
            "SELECT id, state FROM incidents WHERE key=? AND state!='closed' AND last_event_at>?"
            " ORDER BY opened_at DESC LIMIT 1", (key, time.time() - self.window_s)).fetchone()
        if row:
            return row["id"], State(row["state"])
        iid = uuid.uuid4().hex[:8]
        now = time.time()
        self.db.execute("INSERT INTO incidents (id, key, state, agent_id, src_ip, opened_at, last_event_at)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (iid, key, State.COLLECTING.value, ev.agent_id, ev.src_ip, now, now))
        self.audit.append("incident_opened", incident=iid, key=key, first_alert=ev.alert_id)
        return iid, State.COLLECTING

    def _debounce(self, iid, urgent):
        """Run the AI after `quiet_s` without new alerts, never later than `max_wait_s`."""
        if t := self.timers.pop(iid, None):
            t.cancel()
        opened = self._row(iid)["opened_at"]
        delay = 0 if urgent else min(self.quiet_s, max(0.0, opened + self.max_wait_s - time.time()))
        self.timers[iid] = asyncio.get_running_loop().call_later(delay, self._start, iid)

    def _rerun(self, iid):
        if self._row(iid)["runs"] >= self.max_runs:
            self.audit.append("rerun_skipped", incident=iid, reason="model call cap")
            return
        self.transition(iid, State.INVESTIGATING, reason="new evidence")
        self._launch(iid)

    def _start(self, iid):
        self.timers.pop(iid, None)
        self.transition(iid, State.INVESTIGATING, reason="debounce elapsed")
        self._launch(iid)

    def _launch(self, iid):
        self.db.execute("UPDATE incidents SET runs=runs+1 WHERE id=?", (iid,))
        self.db.commit()
        asyncio.create_task(self.on_ready(iid))

    def _row(self, iid):
        return self.db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()

    def _set(self, iid, **cols):
        assigns = ", ".join(f"{c}=?" for c in cols)  # column names come from this module only
        self.db.execute(f"UPDATE incidents SET {assigns} WHERE id=?", (*cols.values(), iid))
        self.db.commit()
