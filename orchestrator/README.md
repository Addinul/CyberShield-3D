# CyberShield orchestrator

The one process that turns Wazuh, Suricata, Cowrie and the AI agent into a single automated system. The only human step is Approve or Reject.

## The automated chain

| Step | What happens | What triggers it | Human? |
|---|---|---|---|
| 1. Collect | Suricata (`eve.json`), Cowrie (`cowrie.json`), auditd and SSH logs leave the victim | One Wazuh agent tails all of them ([victim snippet](../wazuh/victim-agent-ossec.conf.snippet)) | No |
| 2. Contain | Attacker IP redirected to Cowrie, or a process cut off from the network | Wazuh rule → Active Response on the victim, within seconds ([manager snippet](../wazuh/manager-ossec.conf.snippet), [rules](../wazuh/local_rules.xml)) | No |
| 3. Group and investigate | Alerts for one attacker become one incident; the agent runs once the burst settles | Wazuh pushes each alert to `POST /ingest/wazuh` ([webhook script](../wazuh/integrations/custom-cybershield)); the state machine debounces | No |
| 4. Recommend | Rule floors applied, then the confidence × stage table picks the action | `policy.py`, written to the hash-chained audit log, pushed live over `/ws` | No |
| 5. Act | Timed block, account disable, freeze/kill, or release on the victim | Analyst approves → `PUT /active-response` on the Wazuh server API | **Yes, one click** |

## Incident states

`collecting` → `investigating` → `awaiting_decision` → `responding` → `monitoring` → `closed`

- **Debounce:** the AI runs after 30 s without new alerts, never later than 5 min. A download attempt, a session closing, decoy contact or a real login skips the wait.
- **New evidence** sends an incident back to `investigating`, up to 3 AI runs per incident.
- **Containment never waits for this.** Wazuh redirects or isolates on its own; the state machine only decides when the AI is called.

## Files

| File | Job |
|---|---|
| `main.py` | FastAPI app: ingest, incidents, decision, audit check, health, websocket, catch-up search |
| `incidents.py` | State machine, grouping by attacker IP + host, debounce, SQLite store |
| `normalise.py` | Any Wazuh alert → one `Event` shape |
| `policy.py` | Rule floors and the confidence × stage table; fixed action → script mapping |
| `audit.py` | Append-only hash-chained log and its verifier |
| `wazuh.py` | Read-only indexer client (agent, catch-up) and Active Response client (approve path only) |
| `agent_worker.py` | Rules-only stand-in for the LLM agent, same output shape |

## Run it without the lab (dry run)

```bash
pip install -r requirements.txt
```

Bash (Git Bash), from this folder:

```bash
INGEST_TOKEN=lab-token ANALYST_USER=analyst ANALYST_PASS=lab-pass DRY_RUN=1 python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

In a second terminal, replay one full attack (5 failed logins → redirect → Cowrie login → 3 commands → download → disconnect):

```bash
INGEST_TOKEN=lab-token python replay.py fixtures/ssh_bruteforce_session.json
```

Then open `http://127.0.0.1:8000/docs` to look at `GET /incidents`, approve with `POST /incidents/{id}/decision` (user `analyst`, password `lab-pass`), and check `GET /audit/verify`. Twelve alerts become one incident, and with `DRY_RUN=1` the approved action is reported instead of sent.

Tests:

```bash
python -m pytest tests
```

## In the lab

Set `WAZUH_API_URL`, `WAZUH_AR_USER`, `WAZUH_AR_PASS` (Active Response account), `INDEXER_URL`, `INDEXER_USER`, `INDEXER_PASS` (read-only account) and `WAZUH_CA`. Remove `DRY_RUN`. Bind to the host-only address: `--host 192.168.56.1`.

## Still to do

- The real LLM agent loop, with pseudonymised usernames and passwords removed before any cloud call.
- Linking Stage 2 process alerts (no IP) to the login session through auditd.
- Holding containment while a decision is pending, and the overdue escalation.
- The approval screen page; analyst login beyond basic auth; TLS.
- Copying the latest audit hash to a separate machine.
- Verify in the lab: rule 5760, and the `PUT /active-response` body (taken from community examples, not the official reference).
