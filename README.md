# CyberShield – Detect, Deceive, Decide

**Agentic cyber defence with human oversight.** HackAI 2026 (GDEX × ANON × UTAR), Track 01: Agentic Cyber Defence.

> **Wazuh contains, the AI investigates, the human decides.**

> [!WARNING]
> **Work in progress.** This repository is being built for the HackAI 2026 finals on 7 Nov 2026. Some parts work today, some are drafts, and some are still plans. The [status table](#status) says which is which. Nothing here is production-ready.

## What it is

Security teams get more alerts than they can investigate, so real attacks get missed. CyberShield is for the Tier 1 analyst in a security operations centre (SOC) who has to decide quickly and defensibly. It does three things:

- **Contains automatically, without destroying evidence.** An attacker guessing SSH passwords is quietly redirected into a [Cowrie](https://github.com/cowrie/cowrie) honeypot. A suspicious process already running is cut off from the network, but kept running so it can be watched. Both steps are reversible and time-limited.
- **Investigates with an AI agent that can only read.** The agent gathers the evidence, builds a timeline, maps it to MITRE ATT&CK, and rates confidence and attack stage. Every claim cites a log line.
- **Leaves every consequential decision to a person.** A fixed policy table, not the AI, turns those ratings into a recommendation. The analyst approves or rejects it, and Wazuh carries out only what was approved.

It is built on open-source tools: [Wazuh](https://wazuh.com/), [Suricata](https://suricata.io/) and Cowrie. The AI model is a setting: Claude, or a local model when logs must stay on-site.

## How it works

![CyberShield architecture: sensors and decoys feed the Wazuh server; Wazuh contains automatically and pushes alerts by webhook to the CyberShield orchestrator, which runs the AI agent, the policy table and the analyst's decision, and sends approved actions back to Wazuh. Every step goes to a hash-chained audit log.](submission/v2/architecture.png)

Everything runs as one event-driven loop:

1. **Sense:** Suricata, Cowrie and host logs (auditd on Linux, Sysmon on Windows) are collected by Wazuh agents.
2. **Detect:** Wazuh rules raise alerts mapped to MITRE ATT&CK.
3. **Contain:** Wazuh Active Response redirects the attacker or isolates the process, automatically and reversibly.
4. **Investigate:** a webhook pushes each alert to the **orchestrator**. It groups one attacker's alerts into one incident and wakes the agent once the burst settles.
5. **Decide:** the policy table recommends an action, and the analyst approves or rejects it.
6. **Respond:** Wazuh runs the approved action.
7. **Record:** every step goes into a hash-chained, append-only audit log.
8. **Learn:** rejections are reviewed by a person, who tunes rules and thresholds.

## Status

| Part | Status |
|---|---|
| Proposal and design ([2-page v2](submission/v2/CyberShield-proposal-v2.pdf), [full design](proposal.md), [decision log](decisions.md)) | Done |
| [Orchestrator](orchestrator/): webhook intake, incident state machine, policy table, audit log | Working skeleton, tested with recorded alerts |
| [Wazuh config](wazuh/): webhook integration, Cowrie rules, redirect trigger | Drafted, not yet tested in the lab |
| AI agent (LLM tool loop) | Placeholder: rules only, same output shape |
| Redirect and process-isolation scripts | Planned |
| Approval screen (web page) | Planned; the API behind it exists |
| Lab build automation | Planned |
| Evaluation against a Wazuh-only baseline | Planned |

## Try the orchestrator (no lab needed)

This replays one recorded SSH attack. That's 12 Wazuh alerts covering failed logins, the redirect, a decoy login, three commands, a download and a disconnect. Nothing is sent to any real machine (`DRY_RUN=1`).

```bash
cd orchestrator
pip install -r requirements.txt
INGEST_TOKEN=demo-token ANALYST_USER=analyst ANALYST_PASS=demo-pass DRY_RUN=1 python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
cd orchestrator
INGEST_TOKEN=demo-token python replay.py fixtures/ssh_bruteforce_session.json
```

Then open <http://127.0.0.1:8000/docs>. The 12 alerts become **one** incident with a recommendation waiting for approval. See [orchestrator/README.md](orchestrator/README.md) for the full walkthrough. Run the tests with `python -m pytest tests`.

## Repository layout

```
orchestrator/   FastAPI service: webhook intake, incident state machine, policy, audit log, Wazuh clients
wazuh/          ossec.conf snippets, custom rules, the webhook integration script
submission/     the 2-page proposal: v2 (current) and v1 (as first submitted)
proposal.md     full design, version 2 (proposal-v1.md keeps version 1)
decisions.md    every design decision and why
pipeline-diagram.html  hand-drawn pipeline and SSH flow
```

## Safety and responsible use

- **Lab only.** Every test runs in an isolated, host-only virtual network that we own. Attack scripts target lab addresses only, and the lab has no internet access while attacks run.
- **No internet-facing honeypot.** Exposing Cowrie publicly would record real people's activity.
- **No real captured data in this repository.** Fixtures are synthetic and use private lab addresses (`192.168.56.0/24`) or documentation addresses (`198.51.100.0/24`).
- **Read-only AI.** The agent can't change anything. Every change goes through Wazuh Active Response, and anything beyond reversible containment needs an analyst.

Please don't use anything here against systems you don't own or aren't authorised to test. To report a security problem in this code, see [SECURITY.md](SECURITY.md).

## Acknowledgements

- [Wazuh](https://wazuh.com/), [Suricata](https://suricata.io/) and [Cowrie](https://github.com/cowrie/cowrie), the open-source tools this is built on.
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Sharafaldin, Habibi Lashkari and Ghorbani, ICISSP 2018), used for evaluation and not redistributed here.
- Parts of this project were drafted with help from AI coding assistants. The design decisions, and responsibility for them, are the team's.

## Team and licence

Built by a student team for HackAI 2026, Track 01; team details are on the hackathon submission page. Licence: to be decided (see `LICENSE` once added).
