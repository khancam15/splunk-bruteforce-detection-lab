# Splunk Brute Force Detection Lab

**SMB brute-force simulation → Splunk detection → automated case triage with Python and the Splunk REST API**

## Overview

This lab simulates SMB brute-force activity in a controlled virtual environment, detects it in Splunk, and automates case-note generation through the Splunk REST API.

The project demonstrates an end-to-end SOC workflow:
- Threat simulation
- Detection engineering
- Alert triage documentation

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Kali Linux | Attack simulation source |
| Windows 11 VM | Attack target |
| Splunk Enterprise | Ingestion, search, and alerting |
| Splunk Universal Forwarder | Windows log forwarding |
| Python 3 | REST API automation |
| VirtualBox | Virtual networking and isolation |
| smbclient | SMB authentication attempt simulation |

## Lab Architecture

```text
[Kali Linux VM] ---(Host-only Network)---> [Windows 11 VM]
                                                                  |
                                                [Splunk Universal Forwarder]
                                                                  |
                                                [Splunk Enterprise (indexer)]
                                                                  |
                                                     [Python REST API Client]
                                                                  |
                                                     [Automated Case Notes]
```

## Lab Objectives

- Simulate SMB brute-force attempts from Kali to Windows 11
- Forward Windows Security logs (EventCode 4625) to Splunk
- Build SPL detections for brute-force behavior
- Pull detection results programmatically from Splunk REST API
- Generate structured SOC case notes automatically

## Developer Cybersecurity Guardrails

Use this repository only in an isolated and authorized lab.

- Never run attack simulation commands against production or public systems
- Keep all VMs on a lab-only host-only network segment
- Use test accounts only; do not reuse real user credentials
- Rotate any lab credentials after demos or screenshots
- Use least privilege for Splunk API users and tokens
- Store secrets in environment variables, not source files
- Redact IPs, hostnames, usernames, and tokens before publishing screenshots

## GitHub Best Practices for This Lab

- Enable branch protection on main:
  - Require pull requests
  - Require at least 1 approval
  - Require status checks before merge
- Use small, focused pull requests with clear titles
- Use conventional commit messages where possible
- Require secret scanning and Dependabot alerts in repository settings
- Sign commits and tag releases for portfolio milestones
- Keep documentation and evidence in sync for every detection change

## Suggested Secure Development Workflow

1. Create a feature branch for each lab change.
2. Update detection, docs, and evidence together.
3. Run quick quality checks before commit:
    - SPL query sanity check in Splunk
    - Markdown link and formatting check
    - Manual review for secret leakage
4. Open a pull request with:
    - What changed
    - Why it changed
    - Validation evidence (screenshots or output)
5. Merge after review and passing checks.

## Repository Structure

```text
soc-automation-splunk-bruteforce-lab/
|-- queries/          # SPL detection queries used in Splunk
|-- screenshots/      # Lab evidence and validation screenshots
|-- .gitignore
|-- README.md
|-- CONTRIBUTING.md   # Branch, commit, and pull request conventions
|-- LICENSE           # MIT License
|-- SECURITY.md       # Lab and GitHub security practices
|-- soc_automation.py # Splunk REST API triage and case note automation
|-- WALKTHROUGH.md    # Step-by-step walkthrough
```

## Screenshots

See the screenshots directory for evidence of each lab phase, including attack execution, detections, and automated output.

## Walkthrough

See WALKTHROUGH.md for the full step-by-step guide.

## Core Project Files

- queries/ (SPL detection queries)
- screenshots/ (lab evidence)
- .gitignore
- README.md
- SECURITY.md (security policy and reporting guidance)
- soc_automation.py (Splunk REST API automation; reads credentials from SPLUNK_USER and SPLUNK_PASS, retries while Splunk is restarting, and exits 0 done, 1 needs you, 75 try later)
- WALKTHROUGH.md

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

Khaneil Campbell | khancam15

Cybersecurity | SOC Analyst | Blue Team


