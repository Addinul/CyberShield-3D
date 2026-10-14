"""Turn any Wazuh alert (SSH, Suricata, Cowrie, auditd) into one Event shape."""
from dataclasses import dataclass

# Alerts that should wake the AI at once instead of waiting for the debounce timer.
URGENT_COWRIE = {"cowrie.session.file_download", "cowrie.session.closed"}
URGENT_GROUPS = {"decoy_contact", "real_login"}


@dataclass
class Event:
    alert_id: str
    ts: str
    rule_id: int
    level: int
    description: str
    groups: list[str]
    mitre: list[str]
    agent_id: str
    src_ip: str | None
    user: str | None
    cowrie_event: str | None
    full_log: str
    urgent: bool


def normalise(a: dict) -> Event:
    rule, data = a.get("rule", {}), a.get("data", {})
    groups = rule.get("groups", [])
    eventid = str(data.get("eventid", ""))
    cowrie = eventid if eventid.startswith("cowrie.") else None
    return Event(
        alert_id=a["id"],
        ts=a["timestamp"],
        rule_id=int(rule.get("id", 0)),
        level=int(rule.get("level", 0)),
        description=rule.get("description", ""),
        groups=groups,
        mitre=rule.get("mitre", {}).get("id", []),
        agent_id=a.get("agent", {}).get("id", "000"),
        src_ip=data.get("srcip") or data.get("src_ip"),  # Wazuh decoders vs JSON logs
        user=data.get("dstuser") or data.get("username"),
        cowrie_event=cowrie,
        full_log=a.get("full_log", ""),
        urgent=cowrie in URGENT_COWRIE or bool(URGENT_GROUPS & set(groups)),
    )
