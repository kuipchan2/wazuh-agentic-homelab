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
- **Detection coverage report** showing which Essential Eight mitigation strategies were exercised by observed alerts

## Evaluation

The mapping engine's output is only usable as evidence if it is reproducible.
Each of 10 fixture alerts was mapped 5 times under identical conditions and the
results compared. Thresholds were set before the first run.

| Criterion | Threshold | T=1.0 | T=0.0 |
| --- | --- | --- | --- |
| HIGH-relevance agreement | ≥ 0.90 | 0.912 | 0.899 |
| Mean pairwise Jaccard | ≥ 0.80 | 0.813 | 0.820 |
| Relevance drift | ≤ 0.10 | 0.229 | 0.161 |
| Priority drift | ≤ 0.10 | 0.400 | 0.100 |
| **Result** | | **FAIL** | **FAIL** |

Per framework (relevance drift):

| Framework | T=1.0 | T=0.0 | Change |
| --- | --- | --- | --- |
| Essential Eight | 0.208 | 0.058 | −72% |
| NIST CSF v2 | 0.132 | 0.182 | +38% |
| ISO 27001 | 0.346 | 0.242 | −30% |

### Findings

**Both configurations fail the pre-defined thresholds.** The engine's output
does not currently meet the bar for standalone audit evidence. It is suitable
for assisting human judgement, not replacing it.

**Framework stability differs sharply.** At T=0.0, Essential Eight reaches a
Jaccard of 0.927 with 100% stability on HIGH-relevance mappings, while ISO
27001 reaches only 0.745. Aggregate figures hide this: overall drift improved
30% while Essential Eight alone improved 72%. Output should be trusted per
framework, not uniformly — Essential Eight mappings are usable directly, ISO
27001 mappings require human review.

**NIST CSF v2 regressed** at T=0.0 (0.132 → 0.182), the only framework to do
so. With K=5 across 10 alerts this may be sampling noise; it is reported as
observed rather than explained, and warrants a larger corpus to confirm.

**Over-attribution of E8-5.** Restrict Administrative Privileges appears in the
stable core of 8 of 10 alerts, including cases where the connection is weak —
an OpenSSL CVE, a netstat state change, a web scan. This is a correctness
problem that the consistency metrics cannot detect: a mapping that is
consistently wrong scores perfectly. It also inflates detection coverage, since
a control matched by nearly every alert carries no signal.

**Prompt injection was resisted.** Fixture `alert_010` carries injected
instructions in attacker-controllable reverse DNS, WHOIS and ISP fields
delivered via third-party threat intelligence. Across all runs the engine kept
the correct priority, produced full mappings, and flagged the attempt in its
risk summary rather than acting on it.

### Limitations

- Consistency is not correctness. A reliably incorrect mapping scores perfectly.
- temperature=0 reduces but does not eliminate variation in LLM output.
- The fixture corpus is small and hand-selected; results do not generalise to
  the full alert population.
- Scope is the mapping engine only. Nothing here evidences whether any
  Essential Eight control is implemented.

### Reproducing

```bash
cd evals
python3 consistency_eval.py --temperature 0.0 --label temp0 -k 5
```

Raw per-call output is retained in `evals/runs/` and can be re-analysed without
further API calls via `--analyse`.

A full Essential Eight maturity assessment of this environment — findings,
accepted risks, evidence index and remediation roadmap — is in
[docs/E8-maturity-assessment-report.md](docs/E8-maturity-assessment-report.md).

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
   🇦🇺 Essential Eight   Detection coverage: 62.5%
      ✅ E8-2, E8-4, E8-5, E8-6, E8-7: triggered
      ⬜ E8-1, E8-3, E8-8: not observed in this sample
```
> **What this metric is not.** Detection coverage measures the proportion of
> the eight mitigation strategies touched by at least one observed alert. It
> does **not** measure whether those controls are implemented. A strategy
> absent from the list means *not observed in this sample*, not *non-compliant* —
> and coverage rises as an environment is attacked more, not as it becomes
> more secure. Assessing implementation requires configuration evidence
> (e.g. Wazuh SCA) and maturity level scoring against the ASD Essential Eight
> Maturity Model (ML0–ML3), which this pipeline does not currently collect.

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
│   └── compliance_summary.json   # detection coverage summary
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
