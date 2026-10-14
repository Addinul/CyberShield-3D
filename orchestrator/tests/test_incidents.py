"""State machine tests: grouping, dedupe, debounce, call cap, legal transitions."""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit import AuditLog  # noqa: E402
from incidents import IncidentManager, State  # noqa: E402
from normalise import Event  # noqa: E402
from policy import apply_floors, recommend  # noqa: E402


def ev(n, urgent=False, cowrie=None, ip="10.0.0.9"):
    return Event(alert_id=f"a{n}", ts=f"2026-10-20T10:00:{n:02d}", rule_id=5760, level=5,
                 description="x", groups=[], mitre=[], agent_id="001", src_ip=ip, user=None,
                 cowrie_event=cowrie, full_log="", urgent=urgent)


def make(tmp_path, **kw):
    runs = []
    audit = AuditLog(str(tmp_path / "audit.jsonl"))

    async def on_ready(iid):
        runs.append(iid)
        mgr.complete(iid, State.AWAITING_DECISION)

    mgr = IncidentManager(str(tmp_path / "db.sqlite"), audit, on_ready, **kw)
    return mgr, runs, audit


def test_alerts_from_one_attacker_become_one_incident_and_duplicates_are_ignored(tmp_path):
    async def go():
        mgr, runs, _ = make(tmp_path, quiet_s=0.05)
        ids = {mgr.attach(ev(i)) for i in range(5)}
        assert len(ids) == 1
        assert mgr.attach(ev(0)) is None  # same alert ID again (push + catch-up)
        other = mgr.attach(ev(9, ip="10.0.0.77"))
        assert other not in ids
        await asyncio.sleep(0.2)
        return runs
    assert len(asyncio.run(go())) == 2  # one AI run per incident, not per alert


def test_urgent_alert_skips_the_debounce(tmp_path):
    async def go():
        mgr, runs, _ = make(tmp_path, quiet_s=10)
        iid = mgr.attach(ev(1))
        mgr.attach(ev(2, urgent=True, cowrie="cowrie.session.file_download"))
        await asyncio.sleep(0.05)
        return runs, mgr.get(iid)["state"]
    runs, state = asyncio.run(go())
    assert runs and state == State.AWAITING_DECISION.value


def test_max_wait_fires_even_if_alerts_keep_coming(tmp_path):
    async def go():
        mgr, runs, _ = make(tmp_path, quiet_s=0.2, max_wait_s=0.3)
        for i in range(8):  # a new alert every 0.1 s would reset a quiet-only timer forever
            mgr.attach(ev(i))
            await asyncio.sleep(0.1)
        return runs
    assert asyncio.run(go())


def test_call_cap_stops_reruns(tmp_path):
    async def go():
        mgr, runs, audit = make(tmp_path, quiet_s=0.01, max_runs=1)
        mgr.attach(ev(1))
        await asyncio.sleep(0.05)
        mgr.attach(ev(2))  # new evidence while awaiting decision
        await asyncio.sleep(0.05)
        return runs, audit
    runs, audit = asyncio.run(go())
    assert len(runs) == 1
    assert '"rerun_skipped"' in open(audit.path).read()


def test_illegal_transition_raises(tmp_path):
    async def go():
        mgr, _, _ = make(tmp_path, quiet_s=10)
        iid = mgr.attach(ev(1))
        with pytest.raises(ValueError):
            mgr.transition(iid, State.RESPONDING)  # cannot act before investigating
    asyncio.run(go())


def test_audit_chain_detects_edits(tmp_path):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(3):
        audit.append("x", n=i)
    assert audit.verify() == {"ok": True, "entries": 3}
    lines = open(audit.path).read().splitlines()
    lines[1] = lines[1].replace('"n": 1', '"n": 99')
    open(audit.path, "w").write("\n".join(lines) + "\n")
    assert audit.verify()["ok"] is False


def test_floor_and_table():
    events = [ev(1, cowrie="cowrie.session.file_download")]
    assert apply_floors("low", "trying", events) == ("medium", "trying")  # injection can't go below
    assert recommend("medium", "trying") == "keep_in_honeypot"
    assert recommend("medium", "trying", critical_asset=True) == "timed_block"
