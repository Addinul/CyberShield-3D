"""Two Wazuh clients with two different credentials.

Alerts are searched on the Wazuh indexer (port 9200); actions run on the Wazuh
server API (port 55000). The AI side only ever gets the read-only indexer account.
"""
import httpx


class Indexer:
    """Read-only account. Used by the agent worker and the catch-up loop."""

    def __init__(self, url, user, password, ca):
        self.c = httpx.AsyncClient(base_url=url, auth=(user, password), verify=ca)

    async def alerts_since(self, ts, size=500):
        query = {"range": {"timestamp": {"gt": ts}}} if ts else {"range": {"timestamp": {"gt": "now-5m"}}}
        body = {"query": query, "sort": [{"timestamp": "asc"}], "size": size}
        r = await self.c.post("/wazuh-alerts-4.x-*/_search", json=body)
        r.raise_for_status()
        return [h["_source"] | {"id": h["_source"].get("id", h["_id"])}
                for h in r.json()["hits"]["hits"]]


class Server:
    """Active Response account. Used ONLY by the approve path."""

    def __init__(self, url, user, password, ca, dry_run=False):
        self.c = httpx.AsyncClient(base_url=url or "http://unset", verify=ca)
        self.auth, self.dry_run = (user, password), dry_run

    async def run_ar(self, agent_id, script, srcip):
        if self.dry_run:
            return {"dry_run": True, "agent": agent_id, "command": f"!{script}", "srcip": srcip}
        # To verify in the lab: this request body comes from community examples,
        # not the official 4.x API reference.
        tok = (await self.c.post("/security/user/authenticate", auth=self.auth)).json()["data"]["token"]
        r = await self.c.put("/active-response", params={"agents_list": agent_id},
                             headers={"Authorization": f"Bearer {tok}"},
                             json={"command": f"!{script}", "alert": {"data": {"srcip": srcip}}})
        r.raise_for_status()
        return r.json()
