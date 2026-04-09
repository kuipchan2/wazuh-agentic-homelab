# Wazuh Agentic AI Homelab

A hands-on security homelab integrating Wazuh SIEM with AI agents for automated threat detection and triage.

## Architecture

- **Wazuh Stack** — SIEM, log collection, detection rules (Docker)
- **AI Triage Agent** — Reads alerts, classifies threats using Claude AI
- **Enrichment Agent** — IP threat intelligence lookup via AbuseIPDB

## Stack

- Wazuh 4.10.0 (Manager + Indexer + Dashboard)
- Python 3.12
- Anthropic Claude API
- Docker + WSL2

## Structurewazuh-agentic/
├── phase3/
│   └── triage_agent.py        # v1 basic triage
├── phase4/
│   ├── triage_agent_v2.py     # v2 with retry + rate limiting
│   └── enrichment_agent.py    # IP threat intel enrichment## Setup

1. Clone this repo
2. Set environment variables:
```bash
export ANTHROPIC_API_KEY="your-key"
export ABUSEIPDB_KEY="your-key"  # optional
```
3. Start Wazuh stack:
```bash
cd wazuh-docker/single-node
docker compose up -d
```
4. Run triage agent:
```bash
cd phase4
python3 triage_agent_v2.py
```

## MITRE ATT&CK Coverage

- T1110 — Brute Force
- T1078 — Valid Accounts
- T1222 — File and Directory Permissions Modification
