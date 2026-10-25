# Splunk Brute Force Detection Lab

**SOC automation and detection engineering lab: SMB brute-force simulation → Splunk detection → automated case triage with Python and the Splunk REST API**

## Overview

This lab simulates SMB brute-force activity in an isolated virtual environment, detects it in Splunk, and automates case-note generation through the Splunk REST API.

The project demonstrates an end-to-end SOC workflow:

- Threat simulation
- Detection engineering
- Alert triage documentation

**Audience:** hiring managers and security engineers reviewing hands-on blue team work, and anyone rebuilding a similar home lab. Part of [Khaneil Campbell's](https://github.com/khancam15) portfolio; the full case study is at [khaneilcampbell.com](https://khaneilcampbell.com/soc-automation-lab.html).

## Status

Complete as a lab exercise. The attack was run once, the detection fired (81 failed logons in the recorded run), and the script generated the case note shown in the screenshots. This is a home lab, not a production detection; see [Limitations](#limitations).

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Kali Linux | Attack simulation source |
| Windows 11 VM | Attack target |
| Splunk Enterprise | Ingestion, search, and alerting |
| Splunk Universal Forwarder | Windows log forwarding |
| Python 3 (`requests`) | REST API automation |
| VirtualBox | Virtual networking and isolation |
| smbclient | SMB authentication attempt simulation |

## Lab Architecture

```text
[Kali Linux VM] --(host-only network)--> [Windows 11 VM]
                                               |
                                   Splunk Universal Forwarder
                                   (Windows Security log, EventCode 4625)
                                               |
                                               v
                                   [Splunk Enterprise (indexer)]
                                               |
                                   REST API, port 8089
                                               |
                                               v
                                   [soc_automation.py]
                                               |
                                               v
                                   [Markdown case note in notes/]
```

Data path: failed SMB logons on the Windows VM are written to the Security log as EventCode 4625, forwarded to Splunk, aggregated by account and source address in five minute buckets, and pulled by the script, which writes one case note per run.

## Lab Objectives

- Simulate SMB brute-force attempts from Kali to Windows 11
- Forward Windows Security logs (EventCode 4625) to Splunk
- Build SPL detections for brute-force behavior
- Pull detection results programmatically from the Splunk REST API
- Generate structured SOC case notes automatically

## Detection logic

Two versions of the search exist:

- [`queries/brute_force_detection.spl`](queries/brute_force_detection.spl): the search saved in Splunk. Ten or more failed logons from one source against one account within five minutes, excluding loopback, is flagged High.
- The `SPL_QUERY` constant in `soc_automation.py`: the same threshold, extended to collect logon types, failure reasons and host, and to grade severity (20 or more failures is High, otherwise Medium).

Keep both in step when tuning the threshold.

## Running the automation

Prerequisites: Splunk running locally with the management port (8089) reachable, a lab account with search permission, Python 3 and the dependency in `requirements.txt`.

```bash
pip install -r requirements.txt
export SPLUNK_USER="<lab account>"
export SPLUNK_PASS="<lab password>"
python3 soc_automation.py
```

The script authenticates, submits the search as a blocking job, fetches the results as JSON, and writes `notes/soc_case_<timestamp>.md` with one section per alert and recommended next actions. It exits with a message, not a traceback, when Splunk is unreachable, when credentials are missing, or when no alert meets the threshold.

Configuration lives at the top of the script: `SPLUNK_HOST` (default `https://localhost:8089`) and `OUTPUT_DIR` (default `notes`). Credentials are read only from the environment. TLS verification is disabled for the self-signed local Splunk certificate; see Limitations.

Generated notes match the `soc_case_*.md` pattern in `.gitignore`, so they stay out of git.

## Limitations

- Single host, single tenant: the detection assumes `index=main` and the Windows event sourcetype used in this lab.
- `SPLUNK_HOST` is hard coded for a local instance and certificate verification is turned off. Both are acceptable for an isolated lab and would need to change for any shared environment.
- The threshold (10 failures in five minutes) was tuned against one simulated attack, not against baseline traffic.
- The case note is a Markdown file; nothing is pushed to a ticketing system.

## Repository Structure

```text
ssplunk-bruteforce-detection-lab/
|-- queries/
|   `-- brute_force_detection.spl   # SPL detection saved in Splunk
|-- screenshots/                     # Lab evidence, one image per phase
|-- soc_automation.py                # Splunk REST API triage and case note automation
|-- requirements.txt                 # Python dependency (requests)
|-- WALKTHROUGH.md                   # Step-by-step build and attack walkthrough
|-- SECURITY.md                      # Lab and GitHub security practices
|-- CONTRIBUTING.md                  # Branch, commit, and pull request conventions
|-- LICENSE                          # MIT License
`-- .gitignore
```

## Screenshots

The `screenshots/` directory holds evidence of each phase in order: static IP setup, connectivity check, the SMB brute force, Splunk aggregation and threshold detection, event code distribution, the script run, and the generated case note.

## Walkthrough

See [WALKTHROUGH.md](WALKTHROUGH.md) for the full step-by-step guide, from safety pre-checks to validation.

## Safety and contribution rules

Use this repository only in an isolated and authorized lab. Never run the attack simulation against production, public or third party systems, use test accounts only, and redact IPs, hostnames, usernames and tokens before publishing screenshots. The full baseline is in [SECURITY.md](SECURITY.md); branch and pull request conventions are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Built with AI Assistance

I used Claude, Anthropic's AI assistant, as a working partner throughout this lab. I built and ran every part of the environment myself; Claude helped me plan, write, and troubleshoot.

**How I used Claude**

- **Planning:** mapped the attack, detection, and automation workflow before building the lab
- **Python automation:** wrote and debugged `soc_automation.py`, which queries the Splunk REST API and generates triage case notes
- **Documentation:** drafted and refined the README and WALKTHROUGH from my lab notes and screenshots
- **Git troubleshooting:** resolved diverged branches, file naming problems, and `.gitignore` coverage for secrets

**What I did myself**

- Built the Kali Linux and Windows 11 virtual machines and the host-only network
- Ran the SMB brute-force attack and wrote and tuned the Splunk SPL detection
- Ran the script against live Splunk data and checked every output against the raw events

**Responsible use**

- No passwords, tokens, or real user data were ever shared with the AI assistant
- Every AI-generated command and line of code was reviewed and tested before use

## Author

Khaneil Campbell | [khancam15](https://github.com/khancam15)

Cybersecurity | SOC Analyst | Blue Team
