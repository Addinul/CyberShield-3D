"""Rules-only stand-in so the whole loop runs today.

The real version is the LLM tool loop: a separate process holding only the read-only
indexer account, log text passed as untrusted data, usernames pseudonymised and
passwords removed before any cloud call, and output forced into these fields.
"""
from dataclasses import dataclass, field


@dataclass
class Verdict:
    confidence: str
    stage: str
    claims: list[dict] = field(default_factory=list)  # {"text": ..., "alert_id": ...}


async def run_agent(events) -> Verdict:
    claims = [{"text": e.description, "alert_id": e.alert_id} for e in events if e.level >= 6]
    cmds = sum(e.cowrie_event == "cowrie.command.input" for e in events)
    confidence = "high" if cmds >= 3 else "medium" if cmds else "low"
    return Verdict(confidence, "trying", claims)


def check_citations(v: Verdict, events) -> Verdict:
    ids = {e.alert_id for e in events}
    v.claims = [c for c in v.claims if c["alert_id"] in ids]  # drop invented evidence
    return v
