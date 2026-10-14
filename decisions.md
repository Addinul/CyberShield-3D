# Design decisions

Each entry gives what we decided, why, and where it came from. Change one only on purpose, and add a new entry saying what replaced it.

## D1. Track 01, a defensive SOC co-pilot
Track 01 Agentic Cyber Defence. The professor's goal is a countermeasure covering any suspicious or malicious activity, through detection, response or both. We also briefly considered a Track 3 idea; the professor chose Track 1.

## D2. Use Wazuh Active Response for containment, not a separate product
Professor's correction. Wazuh is already integrated, needs less setup, and runs custom scripts in any language: it passes the alert JSON on stdin with an add/delete command, and stateful responses expire through timeouts. Its built-in scripts (firewall-drop, host-deny, route-null, disable-account, netsh) block things but don't isolate processes, so process isolation is a custom script. A Comodo/Xcitium-style full sandbox is a later extension only.

## D3. The honeypot is part of the pipeline, and redirect is automatic
Professor's correction. After failed attempts or suspicious activity, Wazuh automatically reroutes the attacker's **new** connections to Cowrie (NAT redirect 22→2222, for that IP only). Existing sessions are not cut. The redirect is automatic because it is reversible, auto-expiring and changes no data, and evidence must be captured fast.

## D4. Two-stage containment
Stage 1 (before entry) redirects into the honeypot. Stage 2 (after entry) applies the process containment ladder. This fills the "attacker already inside" gap, which redirection can't handle.

## D5. Process containment is a first-class feature
This is Addindon's idea from the cybersecurity exhibition: isolate a suspicious process, keep it running and watched, and kill it later only if needed. The ladder is observe (auto), isolate network (auto, expires), freeze (analyst), kill and quarantine (analyst). It must appear in the pipeline, policy, threat coverage and Phase 1, not just be mentioned.

## D6. Who decides what
Reversible, auto-expiring actions that change no data are automatic: redirect, process network isolation. Block, disable account, freeze, kill, quarantine and release need an analyst. The AI never acts; it proposes. This reconciles automatic redirect with the brief's "human approval before consequential actions". Confirm this with the professor.

## D7. The policy table decides, not the AI
The AI rates confidence and stage, citing evidence, and a fixed table maps them to a recommendation. This keeps decisions consistent and testable, and stops an attacker from talking the agent into a different action. Critical assets shift one column right. Allowlisted IPs and critical services are never auto-contained. Conservative mode turns auto-containment off.

## D8. Redirected ≠ guilty; judge by behaviour (corrected 14 Oct 2026)
Earlier wording said "no legitimate user touches a honeypot, so honeypot activity is ground truth". **That is wrong once redirects are automatic.** A genuine user can be redirected by mistake, and counting arrival as proof is circular. The corrected logic:
- **Redirected sessions:** judge by behaviour inside. A genuine user types their own username, runs ordinary commands, then disconnects confused. An attacker tries default usernames, runs reconnaissance, downloads tools, and attempts persistence. A harmless-looking session gets a "release" recommendation.
- **Standalone decoys** (never advertised, nobody is sent there): any contact is near-certain evidence.
- **Triggers** use signals genuine users rarely produce: bursts of failures, non-existent usernames, a scan followed by failures, or a known-bad IP.
- Evaluation scenario 7 tests a genuine user who is wrongly redirected.

## D9. The proposal describes the final form
The proposal describes the complete system. Phases and the prototype appear only in "Development plan and prototype". Phase 1 is the SSH playbook plus process isolation on Linux.

## D10. Configurable model; confidentiality and cost
The agent can use Claude or a local model (Ollama on the RTX 5070). Usernames and passwords are redacted before any cloud call, and model calls are capped per incident. Alerts are grouped per attacker before the AI sees them, so a flood doesn't multiply calls.

## D11. Secure CyberShield itself
Threats are mapped to the OWASP Top 10 for LLM 2025: LLM01 prompt injection through logs, LLM10 flooding, LLM04 poisoning, LLM09 misinformation, LLM06 excessive agency, LLM02 data disclosure and LLM03 supply chain. Also covered: IP spoofing, interception, audit-log tampering (prevented by the hash chain), and the SSH host-key mismatch that can reveal the honeypot. Log text is always passed to the model as untrusted data.

## D12. Evaluation against a Wazuh-only baseline
Precision is always reported together with recall. The main data is our own lab attacks, which have exact ground truth. CIC-IDS2017 (Monday and Tuesday PCAPs replayed through Suricata) is supporting data only, because of its known label errors.

## D13. Only the redirect and process isolation are automatic (14 Oct 2026)
The threat table had listed an automatic IP block for web attacks and an automatic null route for DoS, which contradicted D6. Now web attacks get automatic isolation only for a process the attack starts, and DoS is alert-only: flood sources are often forged, and D11's "act only on completed connections" rule forbids acting on them. Blocks always need an analyst.

## D14. Policy table redefined; rules set floors (14 Oct 2026, refines D7)
- **Probing** = scans, no login attempts yet. **Trying to get in** = login attempts on a real service, including those now in the honeypot. **Inside** = a real foothold. Its processes are already isolated, so the Inside column decides what happens *after* isolation: lift it, keep it and disable the account, or freeze/kill.
- "Critical assets shift one column right" broke at the edges (no column right of Inside; it could recommend isolating a process that doesn't exist). Replaced by: on a critical asset, confidence counts one level higher.
- Rule-based floors: a download attempt or persistence command means at least medium; contact with a standalone decoy means high; a real login means Inside. The AI can raise a rating but cannot push it below a floor, so injected text can't talk it down.

## D15. Containment is held while a decision is pending (14 Oct 2026)
With auto-expiry alone, malware could get its network back before an analyst answered. While an incident waits for a decision, CyberShield extends the redirect or isolation timeout up to a hard cap, then escalates the incident as overdue. The cap values are still open.

## D16. Pseudonymise usernames instead of redacting them (14 Oct 2026, replaces part of D10)
Blind redaction hid the evidence D8 relies on (which usernames were tried). Real accounts become pseudonyms, common default names (root, admin, test) stay visible, and passwords are removed before any cloud call. A password a wrongly redirected user types into Cowrie is masked before Wazuh stores it, and the user is asked to change it.

## D17. How process isolation works (14 Oct 2026, details D5)
- **Linux:** the attacker's shell and everything it starts move into a quarantine cgroup that a firewall rule cuts off. The sshd session process is left alone, so the session stays up and the attacker stays watched.
- **Freeze:** uses the cgroup freezer, which pauses the whole process tree (SIGSTOP on one PID leaves its children running), plus a memory dump. Memory is only kept as evidence once it is dumped.
- **Windows:** firewall rules are per program, not per process. Isolating a shared system program such as PowerShell is never automatic.
- **Limit:** network isolation doesn't stop local damage such as encrypting files, so the analyst is alerted at once and freeze is one click away.
- **To verify in the lab:** moving a running process tree into a cgroup, and the firewall's cgroup match.

## D18. The redirect also closes connections still guessing (14 Oct 2026)
"Only new connections move" let a brute-force tool's already-open connections keep guessing on the real server. The redirect script now also closes that IP's connections that have not logged in. Logged-in sessions are never cut. Still to verify: how to identify pre-authentication sshd connections reliably.

## D19. Learn = reviewed feedback, not automatic tuning (14 Oct 2026)
Rejections are tagged in the audit log. A person reviews them and approves any rule or threshold change before it applies. This stops an attacker from training the system to ignore them (LLM04 poisoning), and keeps the policy table fixed between reviews.

## D20. Evaluation corrections (14 Oct 2026, refines D12)
- **Unit:** an incident, meaning one attacker source in a 30-minute window. The Wazuh baseline flags an incident if any of its alerts reaches level N, reported at several levels.
- **Gate 2:** CyberShield only sees what Wazuh alerts on, so its recall can't exceed Wazuh's. Gate 2 is now the same recall with higher precision and fewer analyst decisions.
- **CIC-IDS2017:** tests network detection only, because a recording can't be redirected and has no host or honeypot logs.
- **New metric:** isolation effectiveness (can an isolated process still reach the network; how often was a legitimate process isolated).
- **Scenarios:** scenario 5 now uses a user who is *not* allowlisted. Scenario 6 covers a password guessed before the threshold, or a stolen one. Each attack scenario is repeated at least 10 times.

## D21. Honeypot honesty (14 Oct 2026)
- Cowrie is "configured to resemble" the real server (banner, hostname, files), never "identical".
- Cowrie accepts only common default usernames, so a genuine user with their own username is refused.
- Its file downloads go through an isolated gateway or are turned off.
- The real server's SSH host key is **never** copied into Cowrie, because a compromised decoy would then let the attacker impersonate the real server. A host-key warning mostly stops genuine users, which is the safe outcome; brute-force tools ignore it.

## D22. Proposal format (14 Oct 2026)
The hackathon requires a 1–2 page proposal. The Claude Doc now has two tabs:
- **"Submission (2 pages)"** is what gets submitted. Its print version is `submission/proposal-submission.html`, rendered to `submission/CyberShield-proposal-2p.pdf` (2 A4 pages).
- **"Full design (reference)"** is the long version, mirrored in `proposal.md`.

Team details are entered on the hackathon submission page, so the proposal has no team section. The victim VM goes from 4 GB to 6 GB RAM, as headroom for Suricata.

## D23. One orchestrator service ties the system together (professor's request)
The professor approved the proposal but asked that every tool work as one automated system, not separate pieces set up one by one. The runtime answer, built in `orchestrator/` and `wazuh/`:
- **Wazuh is the single collector and the action bus.** One agent per host tails Suricata, Cowrie, auditd and SSH logs. Wazuh rules trigger the automatic containment directly. We add no second log pipeline, because CyberShield and the Wazuh-only baseline must see the same data.
- **Push plus catch-up intake.** Wazuh pushes each alert (level 5+) through a custom integration (`custom-cybershield`) to `POST /ingest/wazuh`. Every 60 s the orchestrator also searches the indexer for anything it missed. Duplicates are dropped by alert ID.
- **An incident state machine with debouncing** groups alerts by attacker IP + host within 30 minutes. The AI runs after 30 s of quiet (5 min at most), or at once on urgent evidence. It re-runs on new evidence, up to 3 runs per incident. Containment never waits for this timer.
- **REST over HTTP, not RPC.** Wazuh, the browser and both Wazuh APIs already speak it, and there is only one service.
- **Two Wazuh credentials.** The AI side gets a read-only indexer account. Only the approve path holds the server API account that can run Active Response, and the action → script mapping is fixed in code, never taken from AI text.

Build automation (Vagrant + Ansible, one `cybershield` command) is the other half of the request and is still to do.

## D24. Proposal version 2 (keep version 1) (14 Oct 2026)
Version 2 of the proposal adds the orchestrator from D23. The architecture diagram's right-hand box is now "CyberShield orchestrator", and the arrow into it is labelled "webhook". The text says everything runs as one event-driven loop. Version 1 is kept unchanged:
- **Submission:** v1 in `submission/v1/` and the doc tab "Submission v1 (as submitted)"; v2 in `submission/v2/` and the doc tab "Submission v2 (2 pages)". Both are 2 A4 pages. D22's paths now refer to the `v1/` copies.
- **Full design:** v1 in `proposal-v1.md` (and the Claude Doc's version history); v2 in `proposal.md` and the doc tab "Full design v2 (reference)".

## Suricata's role (for quick reference)
Suricata is the network sensor. It sees scans, floods, web attacks and unusual outbound connections that host logs miss, and writes `eve.json`, which Wazuh reads natively (`log_format json`). It gives early warning (a scan before login attempts) and corroboration, since high confidence needs two independent sources.
