# CyberShield – Detect, Deceive, Decide

**Agentic Cyber Defence with Human Oversight** · Proposal for HackAI 2026, Track 01 Agentic Cyber Defence

Oct 14, 2026 · @Addindon

## Executive summary

CyberShield is an agentic cyber defence system for organisations that cannot staff a large security team. It watches networks, servers and endpoints, contains attackers automatically without destroying evidence, lets an AI agent investigate every incident, and leaves each consequential decision to a human analyst. It runs on open-source tools (Wazuh, Suricata, Cowrie) with an AI agent powered by Claude, or by a local model when logs must stay on-premises.

Its core idea is to contain first, then decide with evidence. Containment works in two stages. Before an attacker gets in, Wazuh silently redirects them into a Cowrie honeypot configured to resemble the real server, so everything they try becomes evidence.

After an attacker gets in, or malware starts running, the suspicious process is cut off from the network while it keeps running and is watched, instead of being killed blindly. The AI agent combines all the evidence into one incident report, with a timeline, MITRE ATT&CK mapping and a confidence level, citing each log line. The analyst then approves or rejects the recommended response.

In one line: **Wazuh contains, the AI investigates, the human decides.**

Our Phase 1 prototype demonstrates this end to end for SSH brute force and process isolation in a three-VM lab, measured against Wazuh alone. Phases 2 and 3 complete the coverage: web attacks, denial of service, malware, privilege escalation, lateral movement, data theft, interception and Windows endpoints.

## Problem and target user

Security teams receive far more alerts than they can investigate, and many are false positives, so real attacks get missed. Lowering detection sensitivity cuts the noise but also hides real attacks, so the fix has to be smarter triage, not fewer alerts.

Three gaps make this worse:

- **Rules don't investigate.** A SIEM matches events against fixed rules. Its correlation rules catch only patterns written in advance, and it cannot weigh new combinations of weak clues or explain its reasoning.
- **Blocking ends the evidence trail.** Blocking an attacker stops them for now but teaches the defender nothing, and they return from a new address.
- **AI verdicts are hard to trust.** Many AI security tools give a verdict without showing the evidence behind it, and the AI itself can be manipulated by attacker-written text.

**Target user:** a Tier 1 analyst in a security operations centre (SOC), such as the 24/7 managed SOCs that local providers run for Malaysian organisations. They review alerts from endpoint, network and server tools around the clock, and must decide quickly and defensibly.

**Who benefits:** small and mid-sized organisations that cannot staff a large SOC, and the analysts who protect them.

## Proposed solution: the CyberShield pipeline

CyberShield is one pipeline with eight stages, shared by every attack type. Each attack type plugs in as a playbook with its own sensor, detection rule and containment action.

1. **Sense.** Suricata watches network traffic. Wazuh agents collect logs from Linux servers (with auditd) and Windows endpoints (with Sysmon). Cowrie decoys record attacker sessions.
2. **Detect.** Wazuh rules and correlation turn raw events into alerts, mapped to MITRE ATT&CK.
3. **Contain (automatic, reversible).** Attackers trying to get in are redirected into a honeypot; suspicious processes already running are cut off from the network and watched. Both expire on their own and change no data.
4. **Investigate (AI).** The agent gathers every alert about the incident, builds a timeline, and rates confidence and attack stage, citing evidence. It runs again when new evidence arrives.
5. **Decide (human).** The analyst approves or rejects the recommended response.
6. **Respond.** Wazuh executes the approved action: a timed block, a disabled account, a frozen or killed process, a quarantined file, or lifting the containment.
7. **Record.** Every alert, agent step, decision and action goes into a hash-chained audit log.
8. **Learn.** Analyst decisions, especially rejections, are tagged in the audit log. A regular review turns them into proposed rule and threshold changes, which a person approves before they apply.

What makes it different:

- **Contain first, decide with evidence.** Instead of blocking or killing at the first sign of trouble, CyberShield isolates the threat and keeps watching. Destructive actions come later, backed by evidence.
- **Two-stage containment.** Deception before entry and process isolation after entry, so both stages of an intrusion have a containment step that keeps the evidence.
- **Decoy evidence, judged by behaviour.** Standalone decoys sit where no legitimate user has any reason to go, so touching one is near-certain evidence of intent. Someone redirected into a decoy is judged on what they do inside: the usernames they try, the commands they type, the files they download.
- **The AI never acts on its own.** It reads and recommends. A fixed policy and a human control every consequential action.
- **Hardened against attacks on itself,** including prompt injection hidden in attacker-typed commands (see Securing CyberShield itself).

## System architecture

CyberShield has three layers: sensors and decoys across the protected network, a Wazuh server that detects and contains, and the CyberShield core that investigates and asks the analyst.

&#91;embedded content: CyberShield architecture · 3 layers\]

The AI agent only reads from the Wazuh API. Every change to the network or a host goes through Wazuh Active Response, and only the reversible containment steps happen without an analyst.

### Components

| Component | Role | Why this choice | Cost |
| --- | --- | --- | --- |
| [Wazuh](https://documentation.wazuh.com/current/getting-started/use-cases/incident-response.html) | SIEM and response: collects logs, applies rules, runs Active Response on every host | Open source; built-in actions (block an IP, null route, disable an account); custom response scripts in any language | Free |
| [Suricata](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html) | Network intrusion detection at the network edge | Wazuh reads its JSON alerts natively | Free |
| [Cowrie](https://github.com/cowrie/cowrie) | Medium-interaction SSH and Telnet decoys: redirect targets on servers, plus standalone decoy hosts nobody should ever use | Records every login, command and download; an emulated shell with no real system to compromise | Free |
| auditd (Linux), Sysmon (Windows) | Process telemetry: programs started, files touched, connections opened | Feeds process containment decisions; both read by Wazuh | Free |
| AI agent (Python) | Investigates incidents and recommends actions | The model is a setting: Claude for quality, a local model for privacy | Claude per use; local model free |
| Policy engine | Maps confidence and attack stage to a recommendation | Keeps decisions consistent and testable | Free |
| Approval screen | Shows each incident and records the analyst's decision | Keeps a human in control of every consequential action | Free |
| Threat intelligence (AbuseIPDB, VirusTotal) | IP and file reputation lookups | Extra evidence for the agent | Free tiers |

## Containment in two stages

CyberShield contains threats at both stages of an intrusion, and neither stage destroys evidence or takes a service down.

### Stage 1: before entry, redirect into a honeypot

When an attacker starts guessing passwords or probing a service, a custom Active Response script adds a firewall rule that sends only that attacker's new connections to a Cowrie decoy. The decoy is configured to resemble the real server (same SSH banner, hostname and familiar files) and accepts common default usernames with weak passwords, so the attacker believes they have broken in and reveals their tools and intent. The script also closes that IP's connections that are still guessing passwords, so guessing on the real server stops at once. Everyone else still reaches the real service, and the rule removes itself after its timeout.

**Being redirected is not proof of guilt.** The trigger can catch a genuine user, so the verdict comes from behaviour inside the decoy. A genuine user usually tries their own username, is refused (the decoy accepts only common default names) and disconnects; their SSH client may also refuse the decoy's different host key. An attacker tries common default usernames, runs reconnaissance commands and downloads tools. A session that looks harmless is recommended for release. Any password a genuine user typed into the decoy is masked before Wazuh stores it, and the user is asked to change it.

**Standalone decoys are the exception.** Fake servers placed across the network, which nobody is ever sent to, catch attackers exploring after they get in. Any contact with one is near-certain evidence of intent.

### Stage 2: after entry, isolate the process

If an attacker does get in, or malware starts running, the suspicious process is contained step by step instead of being killed blindly:

| Step | What happens to the process | Who decides | Mechanism |
| --- | --- | --- | --- |
| Observe | Keeps running; every file it touches, program it starts and connection it opens is logged | Automatic | auditd (Linux) or Sysmon (Windows), read by Wazuh |
| Isolate and observe | Keeps running, but its network traffic is cut, so it cannot reach its controller or send data out. The SSH session itself stays up, so the attacker keeps typing and stays watched | Automatic; time-limited, held while a decision is pending | Linux: the process and everything it starts move into a quarantine control group (cgroup) that a firewall rule cuts off. Windows: an outbound rule for the program's file, which also affects other copies of that program |
| Freeze | The whole process tree is paused in place, and its memory is dumped as evidence | Analyst | cgroup freezer (Linux) or suspend (Windows), plus a memory dump; can be resumed |
| Kill and quarantine | Stopped; its file moved aside and hashed | Analyst | Custom Active Response script |

**Triggers** include a program started from a session that logged in after many failures, a login from an address never seen before followed by downloads, a program running from a temporary folder, an unknown file hash flagged by VirusTotal, or Suricata seeing the process connect somewhere unusual.

Both stages follow one rule: reversible steps that change no data are automatic and time-limited; anything destructive needs an analyst. Network isolation does not stop damage on the machine itself, such as deleting or encrypting files, so the analyst is alerted at once and can freeze the process with one click. This is the same contain-and-watch idea commercial endpoint products use, applied with open-source tools at two levels. A full sandbox that runs every unknown program inside a virtual container is a later extension (see Development plan and prototype).

## Worked example: an SSH attack, end to end

The attacker is moved into the trap after one burst of failed logins, investigated in the background, and blocked only when an analyst approves.

&#91;embedded content: SSH attack · 3 outcomes, 2 automatic containments, 1 human decision\]

Wazuh sorts each event into one of three outcomes. Nothing odd is logged, and an attack in progress triggers the automatic redirect into the honeypot. An attacker already inside (a real login, with a password guessed before the threshold or a stolen one) is too late to redirect, so their processes are isolated from the network at once, and the analyst decides whether to disable the account or freeze or kill those processes.

### The agent's tools

The agent works in a loop: it chooses a tool, reads the result, and decides what to look at next. Every tool but one is read-only. Its choices matter where fixed rules stop: after a download attempt in the honeypot it pulls Suricata's record of that connection; when a username matches a real account it checks that account's other recent logins; when a session looks harmless it looks up what triggered the redirect, to support a release. Model calls are capped per incident.

| Tool | What it does | Access |
| --- | --- | --- |
| search\_alerts | Finds Wazuh alerts by IP, host, user or time window | Read |
| get\_honeypot\_session | Returns the attacker's Cowrie session: logins, commands, downloads | Read |
| check\_ip\_reputation | Looks up the IP in threat intelligence, e.g. AbuseIPDB | Read |
| map\_to\_attack | Reads the ATT&CK tags on Wazuh alerts and maps honeypot commands, which carry none, to techniques | Read |
| propose\_action | Writes a recommendation for the analyst | Propose only, cannot execute |

### What the analyst receives (illustrative)

> **Incident 12: SSH brute force, attacker trapped in honeypot**
>
> - **Evidence:** a port scan (Suricata), a burst of failed logins (Wazuh), and a honeypot login followed by a download attempt (Cowrie), each linked to its log line
> - **Timeline:** scan, then failed logins, then automatic redirect, then honeypot login, then download attempt
> - **ATT&CK:** Network Service Discovery (T1046), Brute Force (T1110), Ingress Tool Transfer (T1105)
> - **Confidence:** high: inside the honeypot they tried common default usernames, ran reconnaissance commands and attempted a download
> - **Stage:** trying to get in; no foothold on the real server
> - **Recommendation:** block this IP for 24 hours (needs approval)

## Response policy and human oversight

Only reversible containment is automatic: the honeypot redirect and cutting a process off from the network. Anything that affects real users or destroys anything needs an analyst's approval.

| Action | Who decides | Why |
| --- | --- | --- |
| Redirect to honeypot | Wazuh, automatically | Reversible, time-limited, changes no data, and evidence must be captured fast |
| Isolate a process from the network | Wazuh, automatically | Reversible and time-limited; the process keeps running and stays watched |
| Hold containment while a decision is pending | CyberShield, automatically, up to a hard cap | Containment should not lapse only because no analyst has answered yet; at the cap the incident is escalated as overdue |
| Investigate and recommend | AI agent | Reads only; never acts |
| Block, disable an account, freeze or kill a process, quarantine a file, release | Analyst | Affects real users or destroys evidence, so a person must be accountable |

### How the recommendation is chosen

The AI does not pick actions freely. It rates two things, citing evidence: **confidence** that the activity is malicious, and the **stage** the attack has reached. A fixed policy table then maps those ratings to a recommendation, which keeps decisions consistent and testable and limits what any rating can lead to. Rules, not the AI, also set floors: a download attempt or persistence command means at least medium confidence, touching a standalone decoy means high, and a real login means the stage is Inside. Injected text cannot push a rating below what the evidence already shows.

| Confidence | Probing (scans, no login attempts yet) | Trying to get in (login attempts on a real service, including those now redirected to the honeypot) | Inside (a foothold on a real server; its processes already isolated) |
| --- | --- | --- | --- |
| Low | Log only | Lift the redirect, keep logging (approval) | Lift the isolation, keep logging (approval) |
| Medium | Watch list: redirect sooner if logins follow | Keep in the honeypot, alert the analyst | Keep isolated; disable the account (approval) |
| High (e.g. malicious behaviour in the honeypot, or touching a standalone decoy) | Block for a set time (approval) | Block for a set time (approval) | Freeze or kill the process, quarantine its file, disable the account (approval) |

Two adjustments apply. On a critical asset, such as a database server, confidence counts one level higher (low as medium, medium as high). Allowlisted IPs and critical system services are never contained automatically; they always go to the analyst.

### Guardrails on automatic containment

- **Clear triggers:** signals genuine users rarely produce, for example 5 failed logins within a minute, logins to usernames that don't exist, a scan followed by failures, or a program running from a temporary folder.
- **Time limits, held while pending:** both the redirect and process isolation are stateful Active Responses that Wazuh undoes after their timeout. While an incident waits for the analyst, CyberShield extends the timeout up to a hard cap, then escalates the incident as overdue.
- **Nothing is cut mid-task:** logged-in sessions are never cut. The redirect only moves new connections and closes ones still guessing passwords, and isolation cuts only the network.
- **Immediate notice:** the analyst is told at once and can release with one click.
- **Locked-down decoys:** Cowrie runs as an unprivileged user, its port is closed to anyone not redirected, and its file downloads go through an isolated gateway or are turned off.
- **Policy modes:** a conservative mode turns automatic containment off and only alerts, for organisations that want a person to approve every step.

### Audit trail

Every alert the agent reads, every tool it calls, its verdict, the analyst's decision (including rejections) and every executed action are written to an append-only log. Each entry includes a hash of the previous one, so editing any past entry breaks the chain and is detected. The latest hash is copied regularly to a separate machine, so deleting recent entries or rebuilding the whole chain is detected too. Rejections double as a running measure of how often the agent is wrong, and feed the Learn stage.

## Threat coverage

CyberShield covers nine attack types with the same pipeline; only the sensor, rule and containment action change. Whenever an attacker is already inside, the running process is isolated first. The Development plan shows the order in which playbooks are built.

| Attack type | Detected by | Automatic containment | Analyst-approved response |
| --- | --- | --- | --- |
| Reconnaissance (port scans) | Suricata | None; a watch list, so a redirect comes sooner if logins follow | Block |
| SSH or Telnet brute force | Wazuh (authentication logs) | Redirect to a Cowrie decoy | Block, disable account |
| Actual break-in (a real login followed by suspicious activity) | Wazuh, auditd or Sysmon | Isolate the session's processes from the network | Disable account, freeze or kill processes |
| Web attacks (SQL injection, XSS, web-login brute force) | Suricata, Wazuh web-server log rules | Isolate any process the attack starts; otherwise alert only | Timed block, patch the application |
| Denial of service and flooding | Suricata | Alert only, because flood sources are often forged | Timed block of real sources; upstream filtering |
| Malware and malicious files | Wazuh file integrity monitoring with VirusTotal, auditd or Sysmon | Isolate the running process | Kill it, and quarantine or delete the file ([documented by Wazuh](https://documentation.wazuh.com/current/getting-started/use-cases/incident-response.html)) |
| Privilege escalation and persistence (new admin users, scheduled jobs, added SSH keys) | Wazuh audit logs, file integrity monitoring | Isolate the process that made the change | Disable account, revert the change |
| Lateral movement and data theft (internal scanning, unusual outbound traffic, DNS tunnelling) | Suricata, auditd or Sysmon | Isolate the process making the connections | Isolate the host |
| Interception (ARP or DNS spoofing, fake certificates) | arpwatch logs into Wazuh, Suricata TLS and DNS logs | Alert only | Remove the rogue device, fix the network |

Built-in Wazuh actions cover blocking IPs, null routes and disabling accounts ([default scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html)). Everything else, including the honeypot redirect, is a custom Active Response script; Wazuh passes it the full triggering alert, including the attacker's IP ([custom scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)).

**On interception:** detection is only half the answer. Prevention comes from encrypting everything and verifying identities: SSH keys, TLS, and checked server certificates. CyberShield's own traffic is protected the same way (see the next section).

## Securing CyberShield itself

A defence tool is a target too, and an AI that reads attacker-written text can be manipulated. We treat CyberShield as an attack surface and map each threat to the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) and the CIA triad.

| Threat | What goes wrong | Defence | OWASP / CIA |
| --- | --- | --- | --- |
| Prompt injection through logs: commands typed in Cowrie, fake usernames, web URLs and user-agent strings | The agent is talked into calling an attack benign | Log text is passed as untrusted data; output is forced into fixed fields; rule-set floors under every rating; the policy table, not the AI, picks actions; a human approves | LLM01 Prompt Injection · Integrity |
| Alert flooding | A real attack is buried and the AI budget drained | Alerts grouped per attacker before the AI sees them; priority queue; caps on model calls; fallback to plain Wazuh alerting | LLM10 Unbounded Consumption · Availability |
| Log poisoning (forged log lines) | An innocent IP is framed, or the real attacker hidden | Wazuh parses fields; high confidence needs two independent sources to agree | LLM04 Data and Model Poisoning · Integrity |
| IP spoofing to trigger blocks | The defence blocks innocent users | Act only on completed connections; allowlist; blocks expire | Availability |
| Evasion: slow brute force, many IPs, spotting the honeypot | Activity slips under thresholds | Longer time windows; grouping by username and pattern, not just IP; customised Cowrie | Integrity |
| AI misjudgement or invented evidence | A wrong verdict | Every cited log line is checked to exist; confidence shown; a human decides | LLM09 Misinformation |
| An over-powerful agent | The AI takes a damaging action | The agent is read-only, with its own read-only Wazuh API account; actions run only through Wazuh after approval | LLM06 Excessive Agency |
| Attacks on the approval screen | Attacker-typed text runs as script in the analyst's browser, or an approval is forged | All log text is escaped before display; analysts log in; only the approval service holds a Wazuh account that can run Active Response, limited to the listed commands | LLM05 Improper Output Handling · Integrity |
| Stolen credentials | An attacker uses CyberShield's own access | Least-privilege Wazuh API users; secrets kept out of code; internal network only | Confidentiality |
| Sensitive data leaving | Logs are sent to a cloud AI | Real usernames become pseudonyms and passwords are removed before a cloud call, or a local model on the host GPU | LLM02 Sensitive Information Disclosure · Confidentiality |
| Interception of CyberShield's traffic | Alerts or AI calls are read or altered | Encrypted agent-to-manager traffic; HTTPS to the AI API; local model option | Confidentiality, Integrity |
| Audit log tampering | An attacker covers their tracks | Hash-chained log, with the latest hash copied regularly to a separate machine | Integrity |
| Malicious dependencies or models | A backdoored component | Pinned versions from official sources | LLM03 Supply Chain |

**A subtle case:** SSH clients remember each server's identity key, and Cowrie's key differs from the real server's. Brute-force tools ignore this, but a genuine user's client warns or refuses to connect after a redirect, which keeps them from typing into the decoy. We do not copy the real key into Cowrie: if the decoy were compromised, the attacker could impersonate the real server.

## Related work and differentiation

Commercial and open-source tools already triage alerts with AI; none of those we studied combine automatic deception with AI investigation and a human-approved response. Decoys themselves are well established, for example [Thinkst Canary](https://canary.tools/); our contribution is joining them to AI investigation and human approval.

| Product or project | What it does | What we take | What CyberShield adds |
| --- | --- | --- | --- |
| [CrowdStrike Charlotte AI Detection Triage](https://www.crowdstrike.com/en-us/blog/agentic-ai-innovation-in-cybersecurity-charlotte-ai-detection-triage/) | Triages endpoint detections into priority, true or false positive, and a recommended action, under bounded autonomy | Triage output format; human keeps final say | Deception evidence; open-source stack an SME can run |
| [Microsoft Phishing Triage Agent](https://redmondmag.com/articles/2025/08/06/microsoft-rolls-out-phishing-triage-agent-in-security-copilot-public-preview.aspx) | Explains every verdict in plain language; analysts override and give feedback | Explanation for every verdict | Every claim tied to a specific log line |
| [Wazuh-Autopilot](https://github.com/gensecaihq/Wazuh-Autopilot/releases) (open source) | Seven SOC agents on Wazuh: triage, correlation, response planning, two-tier approval | Proof that agents on Wazuh work | Two-stage containment (honeypot redirect, process isolation); decoy evidence judged by behaviour; measured evaluation |
| Raddish Technology GUARDIAN (from exhibition material) | Managed EDR/XDR with a 24/7 SOC across assess, deploy, monitor and refresh stages | Defines our user: the analyst in the monitor stage | An assistant for that analyst |
| EDR auto-containment, e.g. [Xcitium ZeroDwell](https://www.msspalert.com/news/xcitium-launches-endpoint-security-solution-expands-partner-network) | Runs unknown programs in a virtual container until verified | Contain and observe instead of kill | The same contain-and-watch idea at two levels, attacker connections and running processes, with open-source tools |
| [University of Turku thesis](https://www.utupub.fi/handle/10024/178601?show=full) | LLM agents labelling Wazuh alerts; faster triage, but hallucination and privacy risks | Academic baseline; co-pilot, not autopilot | Safeguards for exactly those risks |

Wazuh-Autopilot is the closest existing work, so CyberShield's case rests on three things it does not emphasise: deception as the first response, behaviour inside the honeypot as strong evidence of intent, and published numbers against a Wazuh-only baseline.

## Data and evaluation plan

We judge CyberShield on whether it finds real attacks, raises fewer false alarms than Wazuh alone, and cuts the analyst's workload, using data where the truth is known.

### Data

| Source | What it gives us | Ground truth |
| --- | --- | --- |
| Our own lab attacks (scripted from the Kali VM) | Live, repeatable SSH brute force, scans, honeypot sessions and break-ins | Each script logs its start, end, attacker IP and target |
| Benign activity script on the victim | Realistic noise: normal logins, admin tasks, typos | Everything it does is benign by definition |
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), Monday and Tuesday recordings (about 22 GB of the 51 GB set) | Public benchmark: benign traffic (Monday) and SSH/FTP brute force (Tuesday), replayed through Suricata. It tests only network detection: a recording cannot be redirected and has no host or honeypot logs | Published attack windows and IPs; known labelling errors noted |
| Prompt-injection test set | Attacker commands written to manipulate the agent, typed inside Cowrie | We know which sessions contain injection attempts |

### Metrics

| Metric | Question it answers |
| --- | --- |
| Precision | Of incidents called malicious, how many were? |
| Recall | Of real attacks, how many were caught? |
| Alert reduction | How many raw alerts became how many incidents and analyst decisions? |
| Evidence accuracy | Do the cited log lines exist (checked automatically), and do they support the claim (checked by hand on a sample by two team members)? |
| Time to containment | Seconds from the trigger condition being met to the redirect or isolation rule being in place |
| Isolation effectiveness | Can an isolated process still reach the network, and how often was a legitimate process isolated? |
| Injection resistance | How often an injection attempt changed the verdict |
| Cost and latency | Model calls, time and cost per incident, Claude versus a local model |

**Baseline:** the same metrics for Wazuh's rule levels alone, so every number is a comparison, not a claim. Both are counted per incident: one attacker source in a 30-minute window, which Wazuh flags if any of its alerts reaches the chosen level; we report several levels. CyberShield sees only what Wazuh alerts on, so the aim is the same recall with higher precision and fewer analyst decisions. Each attack scenario is repeated at least 10 times, and precision is always reported with recall, because an agent that flags only the most obvious attack scores perfect precision.

### Test scenarios

1. A single SSH brute force, start to finish.
2. Benign activity only, to count false positives.
3. A needle in a haystack: a noise flood with one real attack hidden inside.
4. Prompt-injection attempts typed inside the honeypot.
5. A legitimate user who is not allowlisted mistyping a password: are they left alone?
6. A break-in with a password guessed before the threshold, or a stolen one: the attacker's processes are isolated from the network while the server keeps serving normal users.
7. A genuine user wrongly redirected: does the agent recognise harmless behaviour, or a host-key refusal with no login, and recommend release?

## Development plan and prototype

CyberShield is built in three phases, each ending in a gate it must pass. The Phase 1 prototype, shown live at the 7 Nov finals, demonstrates the whole pipeline on the most common attack, SSH brute force, plus process isolation after a break-in.

&#91;embedded content: Development roadmap · 3 phases, 2 gates\]

Each gate must pass before the next phase starts: Gate 1 is a live demo from attack to approved response; Gate 2 is matching Wazuh alone on recall while beating it on precision and on the number of analyst decisions.

### Prototype environment

The prototype runs as three virtual machines plus a host program on one laptop (32 GB RAM, RTX 5070 GPU), all on an isolated virtual network. The VMs have no internet while attacks run; only the host laptop stays online, for the Claude API and reputation lookups, which the agent makes itself. Lab addresses are private, so in the lab those lookups use a local test list.

&#91;embedded content: Prototype lab · 3 VMs and the host laptop\]

| Machine | Runs | Resources |
| --- | --- | --- |
| Wazuh server | Wazuh manager, indexer, dashboard and API | 8 GB RAM, 4 vCPU |
| Victim server | Real SSH (port 22), Cowrie (port 2222), Suricata, auditd, Wazuh agent | 6 GB RAM, 2 vCPU |
| Attacker | Kali Linux with scripted attacks | 4 GB RAM, 2 vCPU |
| Host laptop | AI agent, approval screen, audit log, optional local model | Remaining RAM, the GPU |

Key hackathon dates: submission closes Oct 15, 2026, and finalists present live on Nov 7, 2026 at UTAR Kampar.

## Alignment with the hackathon brief

CyberShield answers every judging criterion and every point the [Track 01 brief](https://hackai.my/tracks/cyber-defence) asks the demo to show.

### Judging criteria ([hackai.my](https://hackai.my/))

| Criterion | Weight | How CyberShield answers it |
| --- | --- | --- |
| Technical implementation | 25% | Working three-VM lab; Wazuh, Suricata and Cowrie integrated; custom Active Response; reproducible attack scripts |
| Problem relevance | 20% | Alert fatigue in SOCs; a Tier 1 analyst as the user; built for organisations without a large SOC |
| Effective use of agentic AI | 20% | A tool-using agent that chooses its next step; cited evidence; confidence; read-only by design; stated limitations |
| Cybersecurity value | 20% | Faster containment, fewer false alarms than Wazuh alone, attacker intelligence from the honeypot, hardened against attacks on itself |
| Presentation and usability | 15% | Approval screen showing the evidence, the policy row behind the recommendation, and who each option affects; a live attack-to-block demo |

### What the demo shows

| The brief asks for | Where CyberShield shows it |
| --- | --- |
| Problem and user | SOC analyst drowning in alerts (Problem and target user) |
| Inputs and evidence | SSH logs, Suricata alerts, Cowrie sessions, each cited by line |
| Agent workflow | The agent's tool calls in order, shown in the report and audit log |
| Defensive action | Automatic redirect, then an approved timed block |
| Human approval | Approval screen before every consequential action |
| Results and limitations | Metrics against Wazuh alone, plus the limitations below |

The brief also asks submissions to prove a clear problem, a working flow, evidence of value, human oversight and known limitations; each has its own section here.

## Limitations and risks

These are the known limits of the approach and of our prototype, and how we handle each.

### Limits of the approach

| Limitation | Effect | How we handle it |
| --- | --- | --- |
| A wrongly contained legitimate user fails silently | Their commands go nowhere, or their program loses its network, until containment ends | Clear triggers, allowlist, time limits, instant notice, one-click release; we report the false containment rate |
| Many users can share one address (office or mobile-network NAT) | Redirecting that address catches all of them | Known shared addresses are allowlisted; redirects are short; we report it as a false-positive source |
| Network isolation does not stop damage on the machine itself | An attacker or ransomware can still delete or encrypt files | Instant alert and one-click freeze; on critical assets confidence counts one level higher |
| An isolated process may exit when its connections fail | Some programs stop rather than wait | Isolation cuts only the network, never the server; critical services are allowlisted |
| Windows isolation works per program, not per process | Isolating a shared program such as PowerShell affects every copy on that host | On Windows, isolating a shared system program is never automatic; it goes to the analyst |
| Skilled attackers can spot a honeypot (default settings, a different SSH host key) | They leave before revealing much | Customised decoys; the real host key is never copied, because that would expose the real server's identity |
| AI models can misjudge or invent details | A wrong recommendation | Cited evidence checked automatically; rule-set floors; the policy table and a human make every decision |
| A decoy on a protected server shares that host | A flaw in the decoy could expose the host | Cowrie emulates a shell and runs unprivileged; decoys behind a gateway for high-risk networks |
| Process isolation is not a full sandbox | Unknown programs run normally until something flags them | A full execution sandbox is a later extension |
| A cloud AI costs money per use and sees log data | Cost and confidentiality | Pseudonyms, call caps, and a local model option |

### Limits of the prototype

| Limitation | Effect | How we handle it |
| --- | --- | --- |
| A three-VM lab is smaller and cleaner than a real network | Results may not hold at scale | Report results as lab results; scale is tested in later phases |
| CIC-IDS2017 has known labelling and capture errors ([Lanvin et al.](https://hal.archives-ouvertes.fr/hal-03775466)) | Benchmark numbers carry some noise | Rely mainly on our own lab attacks, where the truth is exact |
| The prototype demonstrates the SSH playbook and process isolation on Linux | Other playbooks and Windows are designed but not yet demonstrated | The Development plan marks what each phase delivers |

## Ethics, safety and data protection

All testing happens in an isolated lab we own, on attacks we run ourselves; no real system or person is attacked or monitored.

- **Isolated network.** The VMs sit on a host-only virtual network. Internet access is enabled only to install packages and removed before any attack runs; only the host laptop stays online, for the AI API.
- **No internet-facing honeypot.** Exposing Cowrie publicly would record real people's activity and needs permission, so it is out of scope.
- **Data minimisation.** The agent receives only the fields it needs. Before anything reaches a cloud model, real usernames become pseudonyms (common default names such as root stay visible, because they are evidence) and passwords are removed; or a local model is used instead.
- **Decoy passwords.** A password that a wrongly redirected user types into the decoy is masked before Wazuh stores it, and the user is asked to change it.
- **Retention.** Honeypot recordings and incident data are kept only for the evaluation period, and deleted when a contained user turns out to be legitimate.
- **Accountability.** Every consequential action needs a named analyst's approval, and the hash-chained audit log records who approved what.
- **Transparency.** Limitations and false-positive rates are reported, not hidden.
- **Responsible use of attack tools.** Attack scripts target only lab addresses and are shared only as part of the project.

## References

1. [HackAI 2026 overview, judging criteria and dates](https://hackai.my/)
2. [HackAI 2026 Track 01: Agentic Cyber Defence brief](https://hackai.my/tracks/cyber-defence)
3. [Wazuh: Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
4. [Wazuh: Default active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html)
5. [Wazuh: Blocking SSH brute-force attacks with Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html)
6. [Wazuh: Incident response use cases](https://documentation.wazuh.com/current/getting-started/use-cases/incident-response.html)
7. [Wazuh: Network IDS integration with Suricata](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
8. [Cowrie SSH and Telnet honeypot](https://github.com/cowrie/cowrie)
9. [Cowrie output event reference](https://docs.cowrie.org/en/latest/OUTPUT.html)
10. [CIC-IDS2017 dataset, University of New Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html); cite Sharafaldin, Habibi Lashkari and Ghorbani, ICISSP 2018
11. [Lanvin et al., Errors in the CICIDS2017 dataset](https://hal.archives-ouvertes.fr/hal-03775466)
12. [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
13. [NIST SP 800-61 Rev. 3, Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
14. [CrowdStrike: Charlotte AI Detection Triage](https://www.crowdstrike.com/en-us/blog/agentic-ai-innovation-in-cybersecurity-charlotte-ai-detection-triage/)
15. [Microsoft Phishing Triage Agent (Redmond Magazine)](https://redmondmag.com/articles/2025/08/06/microsoft-rolls-out-phishing-triage-agent-in-security-copilot-public-preview.aspx)
16. [Wazuh-Autopilot releases](https://github.com/gensecaihq/Wazuh-Autopilot/releases)
17. [Xcitium ZeroDwell Containment (MSSP Alert)](https://www.msspalert.com/news/xcitium-launches-endpoint-security-solution-expands-partner-network)
18. [Oniagbi, Evaluation of LLM Agents for the SOC Tier 1 Analyst Triage Process, University of Turku](https://www.utupub.fi/handle/10024/178601?show=full)
