# Wazuh Agentic AI Homelab

A security operations homelab integrating Wazuh SIEM with AI-powered agents for automated threat detection, triage, enrichment, and **multi-framework compliance mapping**.

Built to demonstrate how LLMs can augment GRC workflows — from real-time alert classification to automated compliance posture assessment across Essential Eight, NIST CSF v2, and ISO 27001.

## Pipeline Architecture

```
Wazuh SIEM (Docker)
    │  alerts (JSON)
    ▼
┌─────────────────────────┐
│  Phase 3–4: AI Triage   │
│  Claude API classifies  │
│  alerts as TRUE/FALSE   │
│  POSITIVE with MITRE    │
│  ATT&CK mapping         │
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│  Phase 4: IP Enrichment │
│  AbuseIPDB threat intel │
│  lookup for source IPs  │
│  (abuse score, country, │
│  ISP, Tor exit node)    │
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│  Phase 5: Compliance    │
│  Mapping Engine         │
│  Claude API maps each   │
│  enriched alert to:     │
│                         │
│  🇦🇺 Essential Eight    │
│  🌐 NIST CSF v2         │
│  📋 ISO 27001:2022      │
│                         │
│  + risk summary         │
│  + remediation actions  │
│  + posture report       │
└─────────────────────────┘
```

## Compliance Mapping Engine (Phase 5)

Each enriched alert is automatically mapped to controls across three compliance frameworks using Claude API, grounded by a structured controls reference file for consistency.

| Framework | Scope | Use Case |
|-----------|-------|----------|
| ACSC Essential Eight | All 8 mitigation strategies | Australian government, critical infrastructure, SOCI Act |
| NIST CSF v2 | 15 subcategories across 6 functions | Global enterprise, consulting engagements |
| ISO 27001:2022 | 24 Annex A controls | Certification-aligned organisations |

For each mapping, the engine provides:
- **Control ID and name** with relevance scoring (HIGH / MEDIUM / LOW)
- **Justification** specific to the alert, not generic
- **Actionable remediation** tailored to the detected threat
- **Executive risk summary** written for non-technical stakeholders
- **Compliance posture report** identifying Essential Eight coverage gaps

### Sample Output

```
============================================================
🔴 Alert: Vulnerability detector - Critical vulnerability detected
   IP: 45.33.32.156 | Priority: CRITICAL
────────────────────────────────────────────────────────────
   🇦🇺 Essential Eight:
      🔴 E8-2: Patch Applications [HIGH]
      🟡 E8-6: Patch Operating Systems [MEDIUM]
      ⚪ E8-5: Restrict Administrative Privileges [LOW]
   🌐 NIST CSF v2:
      ID.RA (IDENTIFY): Risk Assessment
      PR.PS (PROTECT): Platform Security
      DE.CM (DETECT): Continuous Monitoring
   📋 ISO 27001:
      A.8.8: Management of technical vulnerabilities
      A.5.7: Threat intelligence
      A.8.16: Monitoring activities
============================================================

📊 COMPLIANCE POSTURE SUMMARY
   Alerts Mapped: 5
   🇦🇺 Essential Eight Coverage: 62.5%
      ✅ E8-2, E8-4, E8-5, E8-6, E8-7: triggered
      ⬜ E8-1, E8-3, E8-8: gaps identified
```

## Stack

- **Wazuh 4.10.0** — Manager + Indexer + Dashboard (Docker, single-node)
- **Python 3.12** — all agents
- **Anthropic Claude API** — alert triage (Phase 3–4) + compliance mapping (Phase 5)
- **AbuseIPDB API** — IP threat intelligence enrichment
- **Docker + WSL2** — containerised deployment on Windows

## Project Structure

```
wazuh-agentic/
├── phase3/
│   ├── triage_agent.py           # v1 basic AI triage
│   └── triage_report.jsonl       # triage output
├── phase4/
│   ├── triage_agent_v2.py        # v2 with retry + rate limiting
│   ├── enrichment_agent.py       # IP threat intel via AbuseIPDB
│   ├── enrichment_report.jsonl   # enrichment output
│   └── triage_report_v2.jsonl    # v2 triage output
├── phase5/
│   ├── compliance_mapper.py      # multi-framework compliance mapping
│   ├── compliance_controls.json  # E8 + NIST + ISO reference data
│   ├── compliance_report.jsonl   # per-alert compliance mappings
│   └── compliance_summary.json   # posture summary with gap analysis
└── tests/
    └── test_triage_agent.py
```

## Setup

1. Clone this repo
2. Set environment variables:
```bash
export ANTHROPIC_API_KEY="your-key"
export ABUSEIPDB_KEY="your-key"  # optional, basic mode without it
```
3. Start Wazuh stack:
```bash
cd wazuh-docker/single-node
docker compose up -d
```
4. Run the pipeline:
```bash
# Phase 4: Triage + Enrichment
cd phase4
python3 triage_agent_v2.py
python3 enrichment_agent.py

# Phase 5: Compliance Mapping
cd ../phase5
python3 compliance_mapper.py --input ../phase4/enrichment_report.jsonl --limit 10
```

## MITRE ATT&CK Coverage

- T1110 — Brute Force
- T1078 — Valid Accounts
- T1222 — File and Directory Permissions Modification
- T1190 — Exploit Public-Facing Application
- T1595 — Active Scanning

## Roadmap

- [ ] Real-time compliance mapping (webhook integration with Wazuh active response)
- [ ] HTML compliance dashboard with Essential Eight heatmap
- [ ] LLM red teaming module (Garak/Promptfoo) for AI pipeline security testing
- [ ] MITRE ATT&CK → Essential Eight cross-reference mapping
