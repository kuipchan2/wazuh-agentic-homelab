# Essential Eight Maturity Assessment and Security Configuration Review

## Wazuh Agentic Homelab — Development Endpoint

---

# 0. Document Control

| Field | Value |
| --- | --- |
| Document title | Essential Eight Maturity Assessment and Security Configuration Review — Wazuh Agentic Homelab |
| Version | 1.1 |
| Status | Final |
| Classification | INTERNAL |
| Assessment period | 19–20 September 2026 |
| Report date | 20 September 2026 (v1.0); 20 September 2026 (v1.1, post-remediation) |
| Assessor | Kui Pang Chan |
| System owner | Kui Pang Chan |
| Distribution | Author; prospective employers on request |
| Next review | 20 March 2027 |

**Note on independence.** The assessor, the system owner, and the operator are
the same individual. No segregation of duties exists. This is stated in
Section 8 as a limitation on the assurance this report can provide, and is
repeated here so that it is visible to anyone reading only the front matter.

### Revision history

| Version | Date | Author | Change |
| --- | --- | --- | --- |
| 1.0 | 20 Sep 2026 | K.P. Chan | Initial issue |
| 1.1 | 20 Sep 2026 | K.P. Chan | Stage 1 remediation completed and verified; Section 9 added; F-006 scope corrected; RA-002 compensating control verified |


---

## Contents

1. Executive Summary
2. Scope and Objectives
3. Methodology
4. Overall Maturity Rating
5. Detailed Findings
6. Accepted Risks and Exceptions
7. Remediation Roadmap
8. Limitations and Assumptions
9. Remediation Status — Stage 1

Appendix A — Evidence Index
Appendix B — Control Crosswalk
Appendix C — Risk Rating Matrix

---

# 1. Executive Summary

## Assessed maturity: Maturity Level 0

Six Essential Eight mitigation strategies apply to this environment. None
reaches Maturity Level 1. Two further strategies are not applicable to the
scope. Under the ASD Essential Eight Maturity Model the overall rating is the
lowest level attained by any applicable strategy, so the environment is assessed
at ML0.

The assessed system is a single-operator development endpoint holding no
organisational or client data. Ratings throughout reflect that context; the same
technical conditions on a production host would rate higher.

## The three findings that matter

**Patching does not cover the software that is actually vulnerable.** Automated
patching is installed, enabled, running on schedule and reporting success. It
covers packages managed by `apt`. Every one of the eleven high-severity
vulnerabilities on this host sits in packages installed by `pip`, which the
automated process does not manage and never inspects. The oldest was published
in 2017; the most recent, thirteen months before this assessment. No alert,
error or metric reveals the gap — the tool reports that nothing needs upgrading,
and is correct within the only scope it was ever given.

**There is no backup, and the evidence base exists in one place.** No backup
process exists for the monitoring platform's configuration or data, no copy is
held off the host, and no restoration has been tested. The host also does not
forward its logs anywhere. Every finding in this report is supported by evidence
that a single disk failure would destroy.

**The compliance tooling is not reliable enough to be evidence.** The LLM-based
mapping engine used in this environment was evaluated against thresholds fixed
before testing and failed them in both configurations tested. Separately, manual
review found it attributing unrelated alerts to a single control in 8 of 10 test
cases — a correctness defect that consistency measurement is structurally unable
to detect, because a tool that is reliably wrong scores perfectly. The output is
useful for drafting. It is not evidence.

## Immediate actions

Six items totalling under two hours close the cheapest findings and, critically,
establish the logging needed to demonstrate that anything else was done. Sudo
logging does not currently exist, so privileged actions on this host — including
remediation of these findings — leave no durable record.

A further roughly twenty hours across sixty days would advance five of the six
applicable strategies to ML1. Section 7 sequences the work.

## What completion would and would not achieve

**The overall rating would remain ML0.** Application control is not scheduled
for implementation; the risk has been accepted, recorded, and given a review
date of 20 March 2027. One applicable strategy at ML0 holds the overall rating
at ML0 regardless of progress elsewhere.

That is the correct figure to report, and it conceals the entire value of the
work. The current position is six strategies unmitigated, none of them by
decision. The position on completion is one strategy unmitigated, knowingly,
with an owner and a review date. The headline rating cannot distinguish those
two states — which is a reason to read past the headline, not a reason to
discount the work.

## On the reliability of this report

The assessor, system owner and operator are the same individual. Evidence is
held solely on the system under assessment. No process was observed, no
documentation reviewed — none exists — and no second party reviewed the ratings.

This is a self-assessment. Its findings are supported by reproducible evidence,
recorded in Appendix A with the commands used, and its limitations are set out
in Section 8 rather than left to inference. It should be read as a documented
and testable account of one environment's posture, not as independent assurance.

---

# 2. Scope and Objectives

## 2.1 Objective

To determine the maturity of Essential Eight mitigation strategy implementation
on the assessed endpoint, against the ASD Essential Eight Maturity Model, and to
record the evidence supporting each determination.

A secondary objective is to establish whether the LLM-based compliance mapping
engine operating in this environment produces output of sufficient
reproducibility to be relied upon as assessment evidence. That question is
treated as part of the assessment rather than as a tooling matter, because the
answer determines what weight the engine's output can carry in this and future
reports.

## 2.2 Structure of this report

Maturity ratings are made against the Essential Eight only. Four findings
(F-006, F-008, F-009, F-010) fall outside the Essential Eight entirely and carry
no maturity rating; they are mapped to CIS Ubuntu 24.04 and ISO/IEC 27001:2022
in Appendix B and are identified as such at the point they appear.

They are included rather than discarded because the evidence base supports them.
The CIS benchmark executed for this assessment overlaps the Essential Eight only
narrowly — of 125 failed checks, essentially only the privilege-management
subset maps to any Essential Eight strategy. Reporting only the Essential Eight
would discard the majority of what the evidence shows; forcing host firewall or
audit logging findings into Essential Eight strategies would misrepresent a
framework that does not address them. Both are recorded, each against the
framework that actually covers it.

## 2.3 In scope

| Asset | Identifier | Basis for inclusion |
| --- | --- | --- |
| WSL2 Ubuntu 24.04 endpoint | Wazuh agent `001`, hostname `wsl-ubuntu` | Hosts the assessed pipeline and its credentials |
| Compliance mapping engine | `phase5/compliance_mapper.py` | Produces output intended for assessment use |

Assessment covers the state of these assets during the assessment period only.

## 2.4 Out of scope

| Excluded | Reason |
| --- | --- |
| Windows 11 parent host | Not instrumented; no agent deployed. Its firewall is relied upon as a compensating control under RA-002 and is unverified — see Section 8. |
| Wazuh manager, indexer and dashboard containers (agent `000`) | Assessed platform, not assessed subject. Security Configuration Assessment (SCA) results retained as EV-011 to document the exclusion. |
| Network infrastructure | No managed network devices in the environment. |
| Agentic trading platform branch | Separate workload in a separate repository branch; no shared assets with the assessed pipeline. |
| Third-party services (Anthropic API, AbuseIPDB) | Supplier assurance not performed. Their availability and integrity are assumed, not evidenced. |

## 2.5 Applicability determinations

Two Essential Eight strategies are assessed as not applicable to this scope
rather than as unmet:

- **E8-3 Configure Microsoft Office Macro Settings** — no Microsoft Office
  installation exists within scope.
- **E8-4 User Application Hardening** — no web browser, PDF reader or browser
  plug-in is installed within scope.

Both would require rating if the endpoint's role changed to include user-facing
applications. The distinction between *not applicable* and *ML0* is applied
consistently throughout and materially affects the counts in Section 4.

## 2.6 Environment characterisation

The assessed endpoint is a single-operator development and research environment.
It holds no organisational or client data, supports no business process, and
accepts no inbound network connections from outside the parent host.

This characterisation is load-bearing. It is the basis on which several findings
are rated below the level identical technical conditions would attract on a
production host, and it is the basis for both risk acceptances in Section 6. The
conditions on which it depends are enumerated in RA-001 and are testable; if any
ceases to hold, the ratings in this report require revision rather than
extension.

---

# 3. Methodology

## 3.1 Framework and version

Maturity determinations are made against the **ASD Essential Eight Maturity
Model**. Control mappings to NIST CSF v2 and ISO/IEC 27001:2022 Annex A are
provided in Appendix B for cross-reference only; they do not affect the maturity
ratings, which are determined solely against the ASD model.

Maturity is assessed at the strategy level, and the overall rating is the lowest
level attained by any applicable strategy. No averaging, weighting or scoring
out of eight is applied. See Section 4.1.

## 3.2 Evidence sources

| Source | What it establishes | What it cannot establish |
| --- | --- | --- |
| Wazuh Security Configuration Assessment (SCA) module, running the CIS Ubuntu 24.04 Benchmark v1.0.0 | Configuration state of the host at scan time | Whether a configuration is maintained, or whether a process exists behind it |
| Wazuh Vulnerability Detection | Known vulnerabilities in installed packages, with CVE publication dates | Exploitability in this environment; presence of compensating controls |
| Direct host inspection (shell) | Presence or absence of specific files, packages and configuration | Operating effectiveness over time |
| Repository and configuration review | How the environment is defined and deployed | Whether the deployment matches the definition |
| Controlled evaluation of the mapping engine | Reproducibility of engine output | Correctness of engine output — see Section 8 |
| Operator attestation | Facts about process that leave no technical artefact | Anything independently verifiable |

Every evidence item is recorded in Appendix A with the command or API call used,
so that collection can be reproduced rather than taken on trust.

## 3.3 Sampling

No sampling was applied to configuration or vulnerability evidence. The CIS
benchmark was executed in full (279 checks) and the vulnerability index was read
in full (26 records). The environment contains a single in-scope endpoint, so
host-level sampling does not arise.

Sampling does apply to the mapping engine evaluation: ten alerts were selected
by hand to span a range of interpretive difficulty — three unambiguous, four
ambiguous, two low-signal, one carrying an embedded prompt-injection attempt.
This corpus is deliberately constructed and is not representative of the alert
population. Its limitations are stated in Section 8.

## 3.4 Maturity determination

For each applicable strategy:

1. The ML1 requirement was identified from the ASD model.
2. Evidence was assessed against that requirement.
3. Where evidence was absent rather than negative, the strategy was rated ML0
   and the absence recorded — an unevidenced control is not a met control.
4. Where a control was partially implemented but did not satisfy the full ML1
   requirement, it was rated ML0 with the partial implementation described.
   Partial credit is not available under the model.

Step 4 applies to E8-5 and E8-6, both of which have functioning components that
do not amount to ML1. Describing them as ML0 without describing what is in place
would understate the position; describing them as partially compliant would
misstate the model.

## 3.5 Risk rating

Findings are rated using the likelihood and consequence definitions in
Appendix C. Ratings reflect the environment as characterised in Section 2.6, not
a generic production context. Where a rating would differ materially on a
production host, the finding says so explicitly rather than leaving the reader
to infer it.

## 3.6 What was not performed

No process observation, no personnel interviews, and no documentation review
were conducted. No penetration testing or exploitation was attempted. No
independent verification of operator attestation was possible. The consequences
of these omissions are set out in Section 8.

---

# 4. Overall Maturity Rating

## 4.1 Summary

**Assessed maturity: Maturity Level 0.**

Under the ASD Essential Eight Maturity Model, an organisation is assessed at the
maturity level it has achieved across *all* applicable mitigation strategies.
The overall rating is therefore the lowest level attained by any applicable
strategy, not an average and not a count of strategies met. Five of the six
applicable strategies assessed here are at ML0, and one is partially
implemented but does not reach ML1. The overall rating is ML0.

This is stated plainly because the arithmetic invites a more flattering
reading. Six applicable strategies, one partially implemented, might be
presented as "17% complete" or scored out of eight. Neither figure means
anything under the model. A single strategy at ML0 places the whole assessment
at ML0 regardless of how the others perform — the model is deliberately
constructed this way, on the reasoning that an adversary needs only one
unmitigated path.

## 4.2 Per-strategy ratings

| # | Mitigation strategy | Current | Target | Finding |
| --- | --- | --- | --- | --- |
| E8-1 | Application Control | **ML0** | ML1 | F-004 *(risk accepted — RA-001)* |
| E8-2 | Patch Applications | **ML0** | ML1 | F-001, F-002 |
| E8-3 | Configure Microsoft Office Macro Settings | **N/A** | — | Not applicable to scope |
| E8-4 | User Application Hardening | **N/A** | — | Not applicable to scope |
| E8-5 | Restrict Administrative Privileges | **ML0** | ML1 | F-005 |
| E8-6 | Patch Operating Systems | **ML0** | ML1 | F-002 |
| E8-7 | Multi-Factor Authentication | **ML0** | ML1 | F-003 |
| E8-8 | Regular Backups | **ML0** | ML1 | F-007 |

**Applicable strategies: 6. At ML0: 6. At ML1 or above: 0.**

## 4.3 Basis for each rating

**E8-1 Application Control — ML0.** No execution allowlisting mechanism is
present. ML1 requires prevention of unapproved executables in user profile and
temporary directories. AppArmor is installed but failing, and in any case
constrains what permitted programs may do rather than which programs may run; it
does not contribute to this rating. Remediation is not planned — see RA-001. The
rating stands at ML0 notwithstanding that acceptance.

**E8-2 Patch Applications — ML0.** ML1 requires patches for applications to be
applied within two weeks of release, or 48 hours where a working exploit exists.
Eleven High-severity vulnerabilities are outstanding, the most recent published
13 months before assessment and the oldest in 2017. The gap exceeds the ML1
window by more than an order of magnitude.

**E8-5 Restrict Administrative Privileges — ML0.** Partially implemented.
Privileged access is not open, but ML1 requires that privileged accounts be
restricted and their use be identifiable. No sudo log exists, `su` is
unrestricted, and cron permissions are unconfigured. Separately, the operator
account holds `docker` group membership, which is functionally equivalent to
unrestricted root and is not recorded as a privileged assignment. This is the
strategy closest to ML1 and the cheapest to advance, but it does not reach it.

**E8-6 Patch Operating Systems — ML0.** Automated OS patching is configured and
executing, and the `noble-security` pocket is current. However, 174 updates from
`noble-updates` — which carries security fixes not published to the security
pocket — are outside the automated scope and are not tracked, alerted on, or
reviewed. ML1 requires a patching process covering operating system updates
within defined timeframes; a process that excludes a pocket carrying security
content without that exclusion being recorded does not meet it.

**E8-7 Multi-Factor Authentication — ML0.** No MFA mechanism of any kind is
present. Authentication is single-factor. This is an absence, not a partial
implementation.

**E8-8 Regular Backups — ML0.** No backup process exists, no off-host copy is
held, and no restoration has been tested. ML1 requires backups to be performed
and retained in accordance with business continuity requirements, and
restoration to be tested when the backup system is first implemented.

## 4.4 Strategies assessed as not applicable

**E8-3 Configure Microsoft Office Macro Settings.** No Microsoft Office
installation exists within scope.

**E8-4 User Application Hardening.** No web browser, PDF reader, or browser
plug-in is installed within scope.

These are recorded as not applicable rather than ML0 because the scope does not
present the risk each control addresses. The distinction affects the overall
rating: had they been recorded as ML0, the count of failing strategies would
read 8 of 8 rather than 6 of 6, overstating the gap. It also affects
reassessment — both would require rating if this host's role changed to include
user-facing applications.

## 4.5 What would change the rating

The overall rating moves from ML0 to ML1 only when every applicable strategy
reaches ML1. On current findings that requires all six, including E8-1, which is
under accepted risk and therefore not scheduled for remediation.

**The overall rating cannot reach ML1 while RA-001 stands.** This is a direct
consequence of the acceptance, not an oversight in the remediation plan, and it
is recorded here so that the two are read together. An organisation carrying a
deliberate ML0 strategy should understand that it is carrying an ML0 overall
posture, whatever progress is made elsewhere.

Remediating the remaining five would place the environment at ML0-with-one-gap
rather than ML0-across-the-board — a materially different risk position that the
single headline rating does not express. Section 7 sequences that work.

---

# 5. Detailed Findings

Findings are ordered by risk rating, then by finding ID. Each references
evidence recorded in Appendix A. Ratings are derived from the matrix in
Appendix C and reflect the assessed environment as scoped in Section 2 — a
single WSL2 development endpoint with no inbound internet exposure. The same
technical conditions on an internet-facing production host would rate higher.

Target dates are set by risk tier from the assessment date of 20 September 2026:
High within 30 days, Medium within 60, Low within 90. Where the underlying
maturity gap cannot realistically close in that window — F-004 in particular —
the target date is the deadline for a decision recorded in Section 6, not for
full implementation.

---

## F-001 — High-severity vulnerabilities unpatched beyond 13 months

| Field | Value |
| --- | --- |
| Mitigation strategy | E8-2 Patch Applications |
| Current / Target maturity | **ML0** → ML1 |
| Risk rating | **High** |
| Evidence | EV-003 |
| Owner | Kui Pang Chan |
| Target date | 20 October 2026 |

**Observation.** Wazuh Vulnerability Detection identified 26 vulnerabilities on
agent 001 (`wsl-ubuntu`): 11 High, 13 Medium, 2 Low. No Critical. The oldest
High-severity finding, CVE-2017-13716 in `binutils` (CVSS 7.1), was published in
August 2017. The most recent, CVE-2024-41996 in `openssl` (CVSS 7.5), was
published in August 2024 — 13 months prior to assessment. The highest-scoring
finding is CVE-2024-6345 in `setuptools` (CVSS 8.8).

**Assessment against the maturity model.** ASD Essential Eight Maturity Level 1
requires patches for vulnerabilities in applications to be applied within two
weeks of release, or within 48 hours where a working exploit exists. Every High
finding on this host exceeds that window by at least an order of magnitude. The
control is not partially met; it is absent.

**Business impact.** Several affected packages handle untrusted input directly —
`cryptography` and `certifi` govern TLS trust decisions, `Jinja2` renders
templates, `Twisted` handles network protocol parsing. Compromise of any one
provides a path to code execution in the context of the process using it. On
this host that context includes the compliance mapping pipeline, which holds an
API credential.

**Recommendation.** Establish a patching process covering all package managers
in use (see F-002), then remediate the 11 High findings. Record a target
frequency and hold the process to it — a documented monthly cycle that is
actually followed satisfies ML1; an undocumented ad-hoc practice does not,
regardless of how current the packages happen to be on any given day.

---

## F-002 — Automated patching covers only one of two package managers

| Field | Value |
| --- | --- |
| Mitigation strategy | E8-2 Patch Applications, E8-6 Patch Operating Systems |
| Current / Target maturity | **ML0** → ML1 |
| Risk rating | **High** |
| Evidence | EV-004, EV-005 |
| Owner | Kui Pang Chan |
| Target date | 20 October 2026 |

**Observation.** `unattended-upgrades` is installed, enabled, and executing
(observed runs at 01:32 and 01:42 on 20 September 2026). Its configured origins
are `noble`, `noble-security`, and the two Ubuntu ESM pockets; debug output
confirms `noble-updates` and third-party repositories are pinned to -32768 and
therefore excluded. The tool reports "No packages found that can be upgraded
unattended" and exits successfully.

That report is accurate within its own scope and misleading outside it. Every
package identified in F-001 was installed via `pip`, which `unattended-upgrades`
does not manage and never inspects. Separately, 174 packages are available from
`noble-updates`, also outside the automated scope.

**Why this matters more than the individual vulnerabilities.** The patching
control reports healthy while a substantial part of the attack surface sits
outside its remit. There is no alert, no error, and no metric that would reveal
the gap. An assessment relying on configuration evidence alone — confirming
`unattended-upgrades` is enabled and correctly configured — would conclude the
control is operating. It is operating; it is not covering.

**Recommendation.** Enumerate every package manager in use on the host (`apt`,
`pip`, `snap`, `docker`), and either bring each under an automated update
process or document it as an accepted exception with a named owner and review
date. Where a manager is excluded by design, the exclusion belongs in the risk
register (Section 6), not in an unexamined default.

---

## F-003 — No multi-factor authentication

| Field | Value |
| --- | --- |
| Mitigation strategy | E8-7 Multi-Factor Authentication |
| Current / Target maturity | **ML0** → ML1 |
| Risk rating | **Medium** |
| Evidence | EV-006 |
| Owner | Kui Pang Chan |
| Target date | 19 November 2026 |

**Observation.** No MFA PAM module is present or referenced in `/etc/pam.d/`
(`pam_google_authenticator`, `pam_u2f`, `pam_oath` all absent). Authentication
is single-factor throughout.

SCA results against the CIS benchmark show the password policy stack is also incomplete:
`libpam-pwquality` is not installed, and `pam_faillock`, `pam_pwquality` and
`pam_pwhistory` are not enabled. Password expiry, minimum password age, history
depth, and inactive-account lockout are all unconfigured.

**Scope note.** Password policy is supporting evidence for account security; it
is not MFA and does not contribute to E8-7 maturity. The two are reported
together here because they share a remediation path, not because they are
equivalent controls.

**Business impact.** Rated Medium rather than High because this host exposes no
inbound network services — the practical attack path to local authentication is
narrow. The rating would be High on any host accepting remote logins.

**Recommendation.** Implement MFA for local and any future remote
authentication. Separately, install `libpam-pwquality` and enable the four PAM
modules identified above — these address CIS findings in their own right,
independent of E8-7.

---

## F-004 — No application control

| Field | Value |
| --- | --- |
| Mitigation strategy | E8-1 Application Control |
| Current / Target maturity | **ML0** → ML1 |
| Risk rating | **Medium** |
| Evidence | EV-002 |
| Owner | Kui Pang Chan |
| Target date | 19 November 2026 |

**Observation.** No execution allowlisting mechanism is deployed. Any
executable accessible to a user account will run.

AppArmor is present but failing three CIS checks (not installed per policy
expectations, profiles not in enforce mode, profiles not enforcing). This is
worth remediating on its own merits, but AppArmor is a mandatory access control
framework that constrains what permitted programs may do — it does not control
which programs may execute. It does not contribute to E8-1 maturity, and
crediting it would misrepresent the control state.

**Recommendation.** For ML1, application control must prevent execution of
unapproved executables in user profile and temporary directories. On Linux this
requires a dedicated mechanism such as `fapolicyd`. Given the effort involved
and the development nature of this host, an alternative legitimate outcome is a
documented risk acceptance (Section 6) rather than implementation — but the
decision should be recorded, not defaulted into.

---

## F-005 — Administrative privilege controls partially implemented

| Field | Value |
| --- | --- |
| Mitigation strategy | E8-5 Restrict Administrative Privileges |
| Current / Target maturity | **ML0** → ML1 |
| Risk rating | **Medium** |
| Evidence | EV-002 |
| Owner | Kui Pang Chan |
| Target date | 19 November 2026 |

**Observation.** SCA identified the following failures in privilege
management:

| Check | Title |
| --- | --- |
| 35664 | Sudo log file does not exist |
| 35668 | Access to the `su` command is not restricted |
| 35594–35599 | Permissions on `/etc/crontab` and `cron.{hourly,daily,weekly,monthly,d}` not configured |
| 35600–35601 | `crontab` and `at` not restricted to authorised users |
| 35703 | Root user umask not configured |
| 35705 | Default user shell timeout not configured |

The absence of a sudo log is the most significant. Privileged actions are being
taken on this host with no durable record of who took them or when. This
undermines not only E8-5 but any subsequent investigation, and it means the
evidence needed to demonstrate the control at a future assessment does not
exist.

**Additional observation — this host's actual privilege posture.** The user
account is a member of the `docker` group, added during Wazuh deployment.
Docker group membership is functionally equivalent to unrestricted root: any
member can start a container mounting the host filesystem with full privileges.
This does not appear in CIS results because it is not a CIS Ubuntu check, and it
would not appear in any purely automated assessment of this host. It is recorded
here because it materially changes the privilege picture.

**Recommendation.** Enable sudo logging first — it is low-effort and unblocks
evidence collection for everything else. Restrict `su`, correct the cron
permission set, and configure root umask and shell timeout. Separately, record
the `docker` group grant as a deliberate, documented privilege assignment with a
named holder, or remove it.

---

## F-006 — Default credentials in version-controlled configuration

| Field | Value |
| --- | --- |
| Framework | ISO/IEC 27001:2022 A.5.17, A.8.9 |
| Risk rating | **Medium** |
| Evidence | EV-007 |
| Owner | Kui Pang Chan |
| Target date | 19 November 2026 |

**Observation.** The Wazuh deployment retains vendor default credentials across
three accounts: the API users `wazuh-wui` (id 2) and `wazuh` (id 1), and the
indexer account `admin`. All are stored in plain text in `docker-compose.yml`.
The accompanying `.env` file is empty; no secret management mechanism is in use.

**Extent revised at v1.1.** Investigation of repository history during
remediation found the same credentials hardcoded in three pipeline scripts
(`phase3/triage_agent.py`, `phase4/triage_agent_v2.py`,
`phase4/enrichment_agent.py`) and present in the initial commit of the public
repository. The original finding described the deployment configuration only and
understated the extent.

The values themselves are published defaults from the upstream Wazuh
distribution and were never secret. The exposure is therefore not credential
disclosure but the disclosure that this deployment had not rotated them —
and, more materially, a code pattern that would have committed real credentials
had any been set.

Because these are the published defaults from the upstream Wazuh Docker
repository, they are known to anyone who has read the project's documentation.
The credential provides full administrative access to the security monitoring
platform — including the ability to modify detection rules, delete alerts, and
alter the audit trail this assessment depends on.

**Business impact.** An attacker reaching this service could disable the
detection that would otherwise reveal their presence, and could alter or destroy
the evidence base. Rated Medium only because the service is not exposed beyond
the host; on a network-reachable deployment this is High.

**Recommendation.** Rotate both credentials. Move them out of the compose file
into environment variables sourced from a file excluded from version control, or
a secret manager. Confirm the current values were never committed to the
repository history — if they were, rotation alone is insufficient.

---

## F-007 — Backup control not evidenced

| Field | Value |
| --- | --- |
| Mitigation strategy | E8-8 Regular Backups |
| Current / Target maturity | **ML0** → ML1 |
| Risk rating | **High** |
| Evidence | EV-010 |
| Owner | Kui Pang Chan |
| Target date | 20 October 2026 |

**Observation.** No backup process exists. Wazuh Docker volumes
(`wazuh_api_configuration`, `wazuh_etc`, `wazuh_logs`, and the indexer data
volume) are not backed up on any schedule, no copy is held outside the host, and
no restoration has been tested. The control is absent rather than immature.

**Partial mitigation — and its limits.** Pipeline source code is held in a
remote Git repository, which constitutes an off-host copy of that material. It
does not extend to the data this assessment depends on: the alert history, the
SCA results, the vulnerability state index, or the Wazuh configuration and
enrollment keys. Loss of the host would destroy the entire evidence base while
leaving the code intact.

**Why this rates High rather than Medium.** Every other finding in this report
is supported by evidence stored solely on the assessed host. F-009 establishes
that the host does not forward logs off-system; this finding establishes that
nothing else leaves it either. The two combine: a single disk failure, a
corrupted WSL2 image, or a ransomware event destroys all assessment evidence
with no recovery path. Backup failures are also the finding most likely to
remain invisible until the moment it matters — there is no alert for a backup
that was never configured.

**Recommendation.** Define what must survive loss of the host and back only
that up — the Wazuh configuration volumes and the indexer data, not the full
image. Hold at least one copy on separate physical media. Then perform a
restoration test and record its date and outcome: ML1 requires restoration to be
tested when the backup system is first implemented, and an untested backup is an
assumption rather than a control. The test is what converts this finding from
ML0 to ML1 — the backup alone does not.

---

## F-008 — No host-based firewall in effect

| Field | Value |
| --- | --- |
| Framework | CIS Ubuntu 24.04 §4; ISO/IEC 27001:2022 A.8.20 |
| Risk rating | **Low** |
| Evidence | EV-002 |
| Owner | Kui Pang Chan |
| Target date | 19 December 2026 |

**Observation.** Eighteen CIS checks covering `ufw`, `nftables` and `iptables`
fail. No single firewall utility is in use, no default-deny policy exists, and
loopback traffic is unconfigured across all three.

**Scope note.** This finding maps to CIS and ISO 27001, not to the Essential
Eight — the Eight does not address host firewalls. It is included because it
forms part of the configuration baseline assessed in Section 4, not because it
affects E8 maturity.

**Business impact.** Rated Low. WSL2 network traffic transits the Windows host,
where filtering is applied by Windows Defender Firewall outside this
assessment's scope. The finding would rate Medium or High on a standalone Linux
host.

**Recommendation.** Select one firewall utility, apply a default-deny inbound
policy, and remove the others to avoid conflicting rule sets. Alternatively,
document the reliance on host-level filtering as an accepted compensating
control in Section 6.

---

## F-009 — Audit logging not deployed

| Field | Value |
| --- | --- |
| Framework | CIS Ubuntu 24.04 §6; ISO/IEC 27001:2022 A.8.15 |
| Risk rating | **Medium** |
| Evidence | EV-002 |
| Owner | Kui Pang Chan |
| Target date | 19 November 2026 |

**Observation.** `auditd` is not installed and its service is not active.
Related failures: journald rotation, compression and storage unconfigured;
`rsyslog` not forwarding to a remote log host; log file permissions
unconfigured; AIDE not installed and no filesystem integrity checking scheduled.

**Why this is rated above F-008.** Every other finding in this report depends on
evidence, and evidence depends on logging. With no audit daemon, no remote log
forwarding, and no sudo log (F-005), the host cannot produce the records needed
to demonstrate any control is operating over time — nor to reconstruct events
after an incident. Local-only logs are also modifiable by anyone who compromises
the host, which is precisely when they matter.

**Recommendation.** Install and enable `auditd`. Configure journald retention
explicitly rather than relying on defaults. Forward logs off the host — this
host already runs a Wazuh agent, so the transport exists and needs only
configuration.

---

## F-010 — Compliance mapping engine output does not meet audit-evidence standard

| Field | Value |
| --- | --- |
| Framework | ISO/IEC 27001:2022 A.5.23, A.8.29 |
| Risk rating | **Medium** |
| Evidence | EV-008, EV-009 |
| Owner | Kui Pang Chan |
| Target date | 19 November 2026 |

**Observation.** The LLM-based compliance mapping engine used in this
environment was evaluated for reproducibility: ten fixture alerts, five
repetitions each, thresholds fixed before the first run. Both configurations
tested failed those thresholds.

| Criterion | Threshold | T=1.0 | T=0.0 |
| --- | --- | --- | --- |
| HIGH-relevance agreement | ≥ 0.90 | 0.912 | 0.899 |
| Mean pairwise Jaccard | ≥ 0.80 | 0.813 | 0.820 |
| Relevance drift | ≤ 0.10 | 0.229 | 0.161 |
| Priority drift | ≤ 0.10 | 0.400 | 0.100 |

Stability varies sharply by framework. At T=0.0, Essential Eight reaches a
Jaccard of 0.927 with 100% stability on HIGH-relevance mappings; ISO 27001
reaches 0.745 with 24% of mappings drifting in relevance between runs.

**A correctness problem the consistency metrics cannot detect.** E8-5 appears in
the stable core of 8 of 10 fixture alerts, including cases where the connection
is weak — an OpenSSL CVE, a netstat state change, a web scan. The mapping is
perfectly consistent and substantially wrong. A tool that is reliably incorrect
scores full marks on every metric in the table above.

This assessment's own evidence corroborates the concern from the opposite
direction: of 125 failed CIS checks, only the privilege-management subset
(F-005) maps meaningfully to any Essential Eight strategy. Both the automated
mapping and the underlying benchmark converge on E8-5 because that is where the
overlap genuinely is — which makes the engine's habit of attributing unrelated
alerts to E8-5 harder to detect, not easier.

**Recommendation.** Treat engine output as a drafting aid requiring human
review, not as evidence. Adopt per-framework handling: Essential Eight mappings
may be used directly; ISO 27001 mappings must be reviewed before inclusion in
any deliverable. Investigate the E8-5 attribution bias in prompt grounding
before extending the engine to further frameworks.

---

## Findings not raised

The following Essential Eight strategies were assessed as **not applicable** to
this scope rather than ML0. The distinction matters: ML0 means a control that
should exist does not; not applicable means the scope does not present the risk
the control addresses.

| Strategy | Basis |
| --- | --- |
| E8-3 Configure Microsoft Office Macro Settings | No Microsoft Office installation within scope |
| E8-4 User Application Hardening | No web browser, PDF reader, or browser plug-in within scope |

Both would require reassessment if this host's role changed to include
user-facing applications.

---

# 6. Accepted Risks and Exceptions

A risk acceptance is a decision, not an omission. Each entry below records what
is being accepted, on what basis, what conditions make that basis valid, and
what would void it. Entries are reviewed on the stated date regardless of
whether anything has changed.

Accepting a risk does not close the underlying finding. The maturity ratings in
Section 4 and the findings in Section 5 stand as assessed — an accepted E8-1 gap
is still ML0, and is reported as ML0.

---

## RA-001 — Application control not implemented

| Field | Value |
| --- | --- |
| Related finding | F-004 |
| Mitigation strategy | E8-1 Application Control |
| Maturity impact | Remains **ML0**; not remediated |
| Residual risk | **Medium** |
| Accepted by | Kui Pang Chan |
| Date accepted | 20 September 2026 |
| Review date | **20 March 2027** |

**Decision.** Execution allowlisting will not be implemented on this host at
this time.

**Basis.** The assessed system is a personal development and research
environment. It holds no organisational data, processes no data belonging to any
third party, and supports no business process. Implementing `fapolicyd` on a
host whose workload changes weekly would impose ongoing tuning effort
disproportionate to the exposure, and would likely be disabled or bypassed in
practice — a control that is nominally present but routinely overridden is worse
than a documented absence, because it produces false assurance.

**Scope conditions.** This acceptance depends on all of the following remaining
true:

1. The host stores no organisational, client, or personal data beyond the
   operator's own.
2. The host is not reachable from the internet for inbound connections.
3. No production workload, and no workload on behalf of a third party, runs on
   the host.
4. The host is operated by a single named individual.

**Compensating controls.** None claimed. AppArmor is present but failing (F-004)
and does not constrain which executables may run; claiming it here would
misrepresent the control state. The residual risk is carried, not offset.

**Triggers voiding this acceptance.** Any of the following requires immediate
reassessment rather than waiting for the review date:

- Any scope condition above ceases to be true.
- The host begins handling data belonging to an employer or client.
- The pipeline is deployed to any system other than this one.
- Evidence of unauthorised code execution is observed.

**Review commitment.** At review, one of three outcomes is recorded:
implementation, renewed acceptance with a fresh rationale, or scope reduction.
Rolling the acceptance forward without stating a reason is not one of them.

---

## RA-002 — Host-based firewall not configured

| Field | Value |
| --- | --- |
| Related finding | F-008 |
| Framework | CIS Ubuntu 24.04 §4; ISO/IEC 27001:2022 A.8.20 |
| Residual risk | **Low** |
| Accepted by | Kui Pang Chan |
| Date accepted | 20 September 2026 |
| Review date | **20 March 2027** |

**Decision.** No host-based firewall will be configured within the WSL2 guest.

**Basis.** WSL2 network traffic transits the Windows host, where filtering is
applied by Windows Defender Firewall. A second filtering layer inside the guest
would add configuration surface and conflicting rule sets without materially
reducing exposure, given the guest accepts no inbound connections from outside
the host.

**Compensating control.** Windows Defender Firewall on the parent host.
**Verified at v1.1** (roadmap item 1.6): all three profiles enabled with
`DefaultInboundAction: Block`. At verification the inbound action was
`NotConfigured` on every profile — functionally equivalent to Block, since that
is the platform default, but not the result of any configuration decision. It
has since been set explicitly, so that a change to it becomes a visible event
rather than a silent reversion to whatever the platform default happens to be.

Blocked-connection logging was found disabled on all three profiles and has been
enabled. Until that change, the control was blocking traffic without producing
any record of what it blocked — effective but unobservable, the same pattern
recorded in F-009 at the host level.

**Triggers voiding this acceptance.** The guest begins listening on any
interface reachable from outside the host; the pipeline is deployed to a
standalone Linux system; Windows Defender Firewall is found to be disabled or
permissive on verification.

---

## Risks explicitly *not* accepted

Recorded here so that their absence from the list above is visible as a
decision rather than an oversight.

| Finding | Why not accepted |
| --- | --- |
| F-001 Unpatched High vulnerabilities | Remediation is a package upgrade. The effort is minutes; there is no cost basis for acceptance. |
| F-002 Patching coverage gap | Same. Bringing `pip` under a documented update process is low-effort and addresses the root cause of F-001. |
| F-007 No backups | The evidence base for this entire assessment exists in one location with no copy. Accepting this would make every other finding unverifiable after a single failure. |
| F-005 Sudo logging absent | Without it, no privileged action on this host can be evidenced — including the remediation of other findings. |
| F-006 Default credentials | Rotation is a one-off task with no ongoing cost. |

---

## Note on scope versus acceptance

Two Essential Eight strategies — E8-3 Configure Microsoft Office Macro Settings
and E8-4 User Application Hardening — are assessed as **not applicable** and do
not appear in this section. They are not accepted risks. The distinction is
material: an accepted risk exists and is being carried deliberately; a
not-applicable control addresses a risk the scope does not present. Recording a
not-applicable control as an accepted risk would overstate the residual risk
being carried, just as recording an accepted risk as not-applicable would
conceal it.

---

# 7. Remediation Roadmap

## 7.1 Sequencing basis

Work is sequenced by risk reduction per unit of effort, not by finding number
and not strictly by risk rating. Three considerations override a simple
risk-ordered list:

**Evidence-enabling work comes first.** Several findings cannot be demonstrated
as remediated until the means of demonstrating anything exists. Sudo logging
(F-005) and off-host log forwarding (F-009) are prerequisites for evidencing
every other item, including their own remediation. They are scheduled ahead of
higher-rated findings for that reason.

**Root causes precede symptoms.** F-001 lists eleven specific vulnerabilities;
F-002 explains why they were never patched. Remediating F-001 alone clears
today's list and leaves the mechanism that produced it intact — the same
condition recurs within weeks. F-002 is therefore scheduled first and F-001
follows as verification that the corrected process works.

**Low-effort items with no cost basis for deferral are pulled forward.**
Credential rotation (F-006) is a single task with no ongoing burden. Deferring
it to its 60-day tier would be scheduling by category rather than by judgement.

## 7.2 Stage 1 — Quick wins (within 7 days)

Items requiring under an hour each, no ongoing maintenance, and no dependency on
other work.

| # | Action | Finding | Effort | Outcome |
| --- | --- | --- | --- | --- |
| 1.1 | Enable sudo logging | F-005 | 10 min | Privileged actions become evidenced; unblocks verification of all later items |
| 1.2 | Rotate Wazuh API and indexer credentials; move out of `docker-compose.yml` into an untracked env file | F-006 | 30 min | Removes published default credentials from a file with repository exposure |
| 1.3 | Confirm rotated credentials were never committed to Git history | F-006 | 15 min | Rotation is insufficient if prior values are recoverable from history |
| 1.4 | Restrict `su`; correct permissions on `/etc/crontab` and `cron.*`; restrict `crontab` and `at` | F-005 | 30 min | Closes eight CIS checks |
| 1.5 | Configure root umask and default shell timeout | F-005 | 10 min | Closes two CIS checks |
| 1.6 | Verify Windows Defender Firewall configuration on the parent host | RA-002 | 15 min | Tests the compensating control that RA-002 currently assumes without evidence |

**Stage 1 does not advance any strategy to ML1.** It removes the cheapest
findings and establishes the logging needed to evidence later work. Item 1.6 is
included because an unverified compensating control is a weaker position than a
known absent one.

## 7.3 Stage 2 — Patching process (within 30 days)

| # | Action | Finding | Effort | Outcome |
| --- | --- | --- | --- | --- |
| 2.1 | Enumerate every package manager in use (`apt`, `pip`, `snap`, Docker images) | F-002 | 1 hr | Defines the actual patching scope; currently undefined |
| 2.2 | Bring `pip`-managed packages under a documented update process | F-002 | 2 hr | Addresses the root cause of all eleven High findings |
| 2.3 | Decide and document handling of `noble-updates`: include in automation, or record as an exception with owner and review date | F-002 | 30 min | Removes an undocumented default exclusion carrying security content |
| 2.4 | Remediate the eleven High-severity vulnerabilities | F-001 | 1 hr | Verifies 2.2 works; clears the current backlog |
| 2.5 | Define and record the patching cadence and target timeframes | F-001, F-002 | 1 hr | ML1 requires a process, not a currently-patched state |

**Target: E8-2 and E8-6 reach ML1.** Note that 2.5 is what actually achieves
this. A host that happens to be fully patched on assessment day without a
defined process does not meet ML1 — the model assesses the process, not the
snapshot.

## 7.4 Stage 3 — Backup and logging (within 60 days)

| # | Action | Finding | Effort | Outcome |
| --- | --- | --- | --- | --- |
| 3.1 | Define what must survive host loss: Wazuh config volumes, indexer data, enrollment keys | F-007 | 1 hr | Scoping prevents backing up the full image unnecessarily |
| 3.2 | Implement backup to separate physical media | F-007 | 2 hr | Establishes an off-host copy |
| 3.3 | **Perform and record a restoration test** | F-007 | 2 hr | This is what converts F-007 to ML1; the backup alone does not |
| 3.4 | Install and enable `auditd` | F-009 | 1 hr | Closes the audit logging gap |
| 3.5 | Configure journald retention, rotation and compression explicitly | F-009 | 30 min | Replaces unexamined defaults |
| 3.6 | Forward logs off-host via the existing Wazuh agent | F-009 | 1 hr | Logs survive compromise of the host that generated them |
| 3.7 | Install `libpam-pwquality`; enable `pam_faillock`, `pam_pwquality`, `pam_pwhistory`; configure password expiry, history and lockout | F-003 | 1 hr | Closes fourteen CIS checks; supports but does not achieve E8-7 |

**Target: E8-8 reaches ML1.** Item 3.3 is the one that matters and the one most
likely to be skipped. An untested backup is an assumption.

## 7.5 Stage 4 — Multi-factor authentication (within 60 days)

| # | Action | Finding | Effort | Outcome |
| --- | --- | --- | --- | --- |
| 4.1 | Select and implement an MFA mechanism for local authentication | F-003 | 3 hr | Addresses E8-7 directly |
| 4.2 | Record the recovery path for lost second factors | F-003 | 30 min | Single-operator environments have no colleague to reset access |

**Target: E8-7 reaches ML1.**

Item 4.2 is not optional in this environment. MFA on a single-operator host
with no documented recovery introduces a self-lockout risk that did not
previously exist. Implementing a control that creates a new availability risk
without recording the mitigation is a poor trade, not an improvement.

## 7.6 Stage 5 — Tooling reliability (within 60 days)

| # | Action | Finding | Effort | Outcome |
| --- | --- | --- | --- | --- |
| 5.1 | Investigate the E8-5 attribution bias in prompt grounding | F-010 | 3 hr | Addresses a correctness defect the consistency metrics cannot detect |
| 5.2 | Adopt per-framework handling: Essential Eight direct, ISO 27001 human-reviewed | F-010 | 30 min | Matches usage to measured reliability |
| 5.3 | Expand the fixture corpus beyond ten alerts and re-run at K=5 | F-010 | 2 hr | Determines whether the NIST regression is real or sampling noise |
| 5.4 | Record the evaluation thresholds and results in project documentation | F-010 | 30 min | Makes the reliability position visible to anyone using the output |

**No maturity target.** F-010 concerns the assessment tooling, not a control.
Completing this stage does not change any Essential Eight rating; it changes
what weight the output of that tooling can carry.

## 7.7 Not scheduled

**F-004 Application Control (E8-1).** Under accepted risk RA-001. Review date
20 March 2027, at which point one of three outcomes is recorded: implementation,
renewed acceptance with fresh rationale, or scope reduction.

**F-008 Host-based firewall.** Under accepted risk RA-002, contingent on
verification of the compensating control at item 1.6. If that verification fails,
RA-002 is void and this work is scheduled.

## 7.8 Expected position on completion

| Strategy | Current | On completion of Stages 1–5 |
| --- | --- | --- |
| E8-1 Application Control | ML0 | **ML0** *(accepted)* |
| E8-2 Patch Applications | ML0 | ML1 |
| E8-5 Restrict Administrative Privileges | ML0 | ML1 |
| E8-6 Patch Operating Systems | ML0 | ML1 |
| E8-7 Multi-Factor Authentication | ML0 | ML1 |
| E8-8 Regular Backups | ML0 | ML1 |
| **Overall** | **ML0** | **ML0** |

The overall rating does not move. Five of six applicable strategies advance to
ML1, and the sixth remains at ML0 by deliberate decision — which under the
model holds the overall rating at ML0.

This is the correct outcome to report, and it is worth stating why the work is
nonetheless worthwhile. The current position is six strategies unmitigated. The
position on completion is one strategy unmitigated, knowingly, with the decision
recorded, an owner named, and a review date set. The headline rating is
identical; the risk carried is not. Where a single summary figure cannot
distinguish those two states, the figure should not be the basis for deciding
whether the work is done.

---

# 8. Limitations and Assumptions

This section states what this assessment does not establish. It is placed before
the appendices rather than in a footnote because several limitations are
material enough to change how the findings should be read.

## 8.1 The environment is not a representative endpoint

WSL2 is a virtualised Linux environment hosted under Windows. It lacks a
bootloader, a graphical login manager, physical network interfaces, and a
complete systemd implementation. Sixty-five of 279 CIS checks (23%) returned
*not applicable* for this reason — bootloader password, GDM configuration and
wireless interface checks cannot evaluate against components that do not exist.

Two consequences follow.

The reported CIS score of 41 is calculated as 89 pass / (89 pass + 125 fail) and
excludes not-applicable results from its denominator. **It should not be read as
41% compliance with the CIS Ubuntu 24.04 benchmark.** Nearly a quarter of the
benchmark returned no determination.

More importantly, findings from this host do not transfer to a production Linux
endpoint. The control conditions observed here are real, but the environment
lacks whole categories of attack surface that a production host presents, and
presents at least one — the WSL/Windows boundary — that this assessment does not
examine at all.

## 8.2 Benchmark and agent version mismatch

Wazuh 4.10.0 ships a CIS policy for Ubuntu 22.04 only. On this 24.04 host that
policy fails its own version check and is skipped, producing no SCA results at
all. The 24.04 policy used in this assessment was obtained from the Wazuh source
repository at tag v4.13.0 and installed manually.

The benchmark therefore matches the operating system, but the policy file
version (4.13.0) does not match the agent version (4.10.0). The SCA YAML schema
appears stable across these versions and no parse errors were observed, but
compatibility is assumed rather than established. Individual check results
should be verified before being acted upon.

## 8.3 Point-in-time evidence only

Every item in Appendix A is a snapshot taken during a single assessment window.
Nothing in this report evidences that any control operated over any period.

This is not a technicality. The Essential Eight assesses processes, not states.
A host that is fully patched on the day of assessment, with no defined patching
process behind it, does not meet ML1 — and this assessment cannot distinguish
that case from a host maintained by a disciplined process, because both produce
the same snapshot. Where maturity has been determined, it rests on evidence of
process configuration, not on evidence of process operation.

Section 7 item 2.5 addresses this for patching specifically: defining and
recording a cadence is what achieves ML1, not the packages happening to be
current.

## 8.4 Configuration evidence is not control effectiveness

This assessment produced a direct demonstration of the gap between the two.

Automated patching (`unattended-upgrades`) is installed, enabled, correctly
configured, executing on schedule, and reporting success. Every configuration
check passes. An assessment relying on configuration evidence alone would rate
the control as operating.

It is operating. It also does not cover `pip`-managed packages, which is where
all eleven High-severity vulnerabilities on this host reside. No alert, error or
metric reveals the gap; the tool reports "no packages found that can be upgraded
unattended" and exits zero.

Every other configuration-derived finding in this report carries the same
exposure. A passing CIS check establishes that a setting has a value. It does
not establish that the setting covers what it needs to cover, that anyone
reviews it, or that it will still hold next week.

## 8.5 The assessment tooling is not reliable enough to be evidence

The LLM-based compliance mapping engine was evaluated for reproducibility and
failed the thresholds set before testing, in both configurations tested. Full
results are in F-010 and EV-008/EV-009.

Three limitations follow for any use of that output.

**Consistency was measured; correctness was not.** A mapping that is reliably
wrong scores perfectly on every metric applied. The E8-5 over-attribution
described in F-010 — present in the stable core of 8 of 10 fixture alerts,
including cases with weak connection — is invisible to consistency measurement
and was identified by manual review.

**The fixture corpus is small and deliberately constructed.** Ten alerts,
hand-selected to span interpretive difficulty. Results do not generalise to the
alert population, and the apparent NIST CSF v2 regression at temperature 0
(0.132 → 0.182 drift) falls within a range that ten alerts at K=5 cannot
distinguish from sampling noise.

**Ground truth was authored by the operator.** The accuracy spot-check compares
engine output against mappings written by the same person who built the engine
and wrote this report. It is recorded as a spot-check for that reason and
carries correspondingly limited weight.

## 8.6 No process, personnel or documentation evidence

No process was observed in operation. No personnel were interviewed. No
documentation was reviewed, because none exists. Every finding rests on
automated collection or on operator attestation.

This bounds what the report can claim. A control can be correctly configured and
routinely bypassed. A backup can exist on paper and fail on restoration. This
assessment would not detect either.

EV-010 is explicitly attestation-based: no artefact can demonstrate the absence
of a backup process, so the finding rests on the operator's statement that none
exists.

## 8.7 No independence

The assessor, system owner and operator are the same individual. There is no
segregation of duties, no review by a second party, and no chain of custody for
evidence — which is held solely on the system under assessment, in a location
that the assessed party can modify.

This is inherent to a single-operator environment and is stated rather than
mitigated. It bears directly on how much assurance this report provides: an
assessment in which the same person selects the scope, collects the evidence,
determines the ratings, and decides what risks to accept is a self-assessment,
whatever its rigour.

## 8.8 Assumptions

The following are assumed and were not verified:

| Assumption | Where it matters | Consequence if false |
| --- | --- | --- |
| ~~Windows Defender Firewall is enabled and appropriately configured on the parent host~~ | RA-002 | **Verified at v1.1** — no longer an assumption. See Section 9.1 item 1.6. |
| The SCA YAML schema is compatible between versions 4.10.0 and 4.13.0 | All EV-002 results | Individual check results may be unreliable |
| CVE publication dates reported by the Wazuh feed are accurate | F-001 maturity determination | Vulnerability ages, and therefore the ML0 determination for E8-2, would require recalculation |
| Third-party services (Anthropic API, AbuseIPDB) operate with integrity | F-010, pipeline output generally | Engine output could be influenced by a supplier without detection |
| ~~No credential in `docker-compose.yml` was ever committed to repository history~~ | F-006 | **Tested at v1.1 and found false.** Credentials were committed, in pipeline source rather than the Compose file. See Section 9.3.1. |

Two of these five were tested in Stage 1. One held; one did not, and the finding
it supported was revised accordingly (Section 9.3.1). The remaining three would
require capability or access outside the scope of this assessment.

That one of two tested assumptions proved false is worth weighing when reading
the three that remain untested.

---

# 9. Remediation Status — Stage 1

Stage 1 of the roadmap in Section 7 was completed on 20 September 2026,
immediately following issue of version 1.0. This section records what was done,
what was verified, and what the work changed — including three matters that
only surfaced during remediation.

Maturity ratings in Section 4 are **unchanged**. Stage 1 was scoped to
evidence-enabling work and low-cost items; it was never expected to advance any
strategy to ML1, and it did not.

## 9.1 Completed items

| # | Action | Finding | Verification |
| --- | --- | --- | --- |
| 1.1 | Sudo logging enabled via `/etc/sudoers.d/10-logfile` | F-005 | `visudo -c` parsed OK; log entries confirmed at `/var/log/sudo/sudo.log` from the moment of configuration |
| 1.2 | API credentials rotated for `wazuh-wui` | F-006 | New credential authenticates; **prior credential returns `Unauthorized`** |
| 1.3 | Repository history searched for committed credentials | F-006 | Found — see 9.3 |
| 1.4 | `su` restricted to `sugroup`; cron permissions corrected; `cron.allow` / `at.allow` established | F-005 | `/bin/su` now `4750 root:sugroup`; `su` denied to non-members, permitted to members; `crontab -l` functional for allow-listed user |
| 1.5 | Root umask `027`; shell timeout 900s | F-005 | Configuration files present and readable |
| 1.6 | Windows Defender Firewall verified and explicitly configured | RA-002 | All three profiles: enabled, `DefaultInboundAction: Block`, `LogBlocked: True` |

Item 1.2 was verified in both directions. Confirming that a new credential works
does not establish that the old one stopped working, and only the second test
distinguishes a rotation from an addition.

## 9.2 CIS checks closed

Ten checks move from fail to pass: 35664 (sudo log file), 35668 (`su`
restriction), 35594–35599 (cron file and directory permissions), 35600–35601
(`crontab` and `at` restricted to authorised users), 35703 (root umask), 35705
(shell timeout).

A re-scan will confirm. These are recorded as expected outcomes pending that
verification, not as verified results — the distinction matters, since several
CIS checks test conditions more specific than the remediation applied.

## 9.3 Matters arising during remediation

Three items surfaced that were not visible to the original assessment. Each is
recorded here rather than quietly folded into the findings above.

### 9.3.1 Credentials were hardcoded in pipeline source and committed

F-006 as issued described default credentials in `docker-compose.yml`. Searching
repository history found the same credentials hardcoded in three pipeline
scripts and present in the initial public commit.

The credentials are published upstream defaults and were never secret, so this
is not credential disclosure. It is disclosure that the deployment had not
rotated them, and — materially — evidence of a pattern that would have committed
real credentials had any been set.

Credentials were removed from all three scripts and replaced with
`os.getenv()` lookups before rotation, so that rotation did not break the
pipeline. F-006 has been revised to reflect the true extent.

**History was not rewritten.** The values in history are public defaults and are
useless against the rotated credential; rewriting history would invalidate every
existing clone for no security gain. This is a decision, not an omission, and is
recorded as such.

### 9.3.2 A second API account remains on default credentials

Enumerating API users during rotation revealed two accounts: `wazuh-wui` (id 2)
and `wazuh` (id 1). Only `wazuh-wui` was known to the original assessment, and
only it was rotated. **`wazuh` remains on its default credential.**

This is an incomplete remediation, recorded as such rather than presented as a
closed item. It is scheduled with the Stage 2 credential work.

The finding behind it is worth stating plainly: the original assessment
enumerated the credentials visible in a configuration file, not the accounts
that actually exist on the system. Configuration is where credentials are
declared; it is not an inventory of what is live.

### 9.3.3 Rotation initially failed with an unhelpful failure mode

The first two rotation attempts set the credential through the Compose
environment variable and recreated the container. Both caused the manager to
enter a restart loop. The cause was a password complexity check
(`WazuhError 5007 — Insecure user password provided`) enforced by the
initialisation script against the regex
`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$`.

Two observations follow.

**The control worked.** A weak credential was rejected rather than accepted.
That is the correct behaviour.

**The failure mode did not.** Rejection surfaced as a container restarting
indefinitely, not as a validation error. The operator saw a broken service, not
a rejected password, and the diagnosis required reading container logs. A
control that is correct but fails opaquely costs time and invites the wrong
remediation — in this case, two rollbacks before the cause was identified.

Rotation succeeded via the running API (`PUT /security/users/2`), which returns
the validation error directly and does not restart the service. The Compose
environment variable was then updated to match, so that a future recreate does
not reintroduce the mismatch.

### 9.3.4 A benchmark recommendation conflicted with operability

CIS check 35600 expects `/etc/cron.allow` at mode 640. Applying it made the file
unreadable to the non-privileged users listed inside it, and `crontab` failed
with `Permission denied` for an explicitly authorised user.

Mode 644 was adopted instead. The access control the file provides — an
allow-list — remains fully effective; only the file's own read permission is
broader. **CIS check 35600 will continue to fail**, and that is accepted rather
than concealed.

Recorded as an exception: a benchmark recommendation was not implemented as
written because implementing it disabled the function it was protecting.
Accepting a permanently failing check is preferable to reporting a passing check
against a control that does not work.

## 9.4 Position after Stage 1

| Strategy | Before | After |
| --- | --- | --- |
| E8-1 Application Control | ML0 | ML0 *(accepted, RA-001)* |
| E8-2 Patch Applications | ML0 | ML0 |
| E8-5 Restrict Administrative Privileges | ML0 | ML0 |
| E8-6 Patch Operating Systems | ML0 | ML0 |
| E8-7 Multi-Factor Authentication | ML0 | ML0 |
| E8-8 Regular Backups | ML0 | ML0 |
| **Overall** | **ML0** | **ML0** |

Nothing moved, as expected.

What changed is not visible in the table. Privileged actions on this host now
leave a durable record, so the remediation of everything that follows can be
evidenced — which it could not have been before item 1.1. A published default
credential no longer grants API access. The compensating control underpinning
RA-002 has been tested rather than assumed. And the assessment's own picture of
the environment is more accurate than it was at issue: two of the three matters
in 9.3 are corrections to findings, not new problems.

Stage 2 remains as scheduled in Section 7, with two additions: rotation of the
`wazuh` account credential (9.3.2), and rotation of the indexer and dashboard
credentials, which were deferred from Stage 1 because they require regenerating
password hashes rather than a configuration change.

---

# Appendix A — Evidence Index

All evidence was collected on 19–20 September 2026 from the systems defined in
Section 2. Timestamps are recorded as reported by the source system; the
timezone is stated per entry because sources differ (Wazuh API and indexer
report UTC, local shell and agent logs report AEST, UTC+10).

Each entry records the command or API call used, so that a reviewer can
reproduce the collection rather than relying on the extract below.

---

## A.1 Evidence register

| ID | Subject | Source | Collected | Referenced by |
| --- | --- | --- | --- | --- |
| EV-001 | Agent inventory | Wazuh API `/agents` | 20 Sep 2026 (UTC) | Section 2 |
| EV-002 | CIS Ubuntu 24.04 SCA results | Wazuh API `/sca/001` and `/sca/001/checks/cis_ubuntu24-04` | 20 Sep 2026 01:40:55 UTC | F-004, F-005, F-008, F-009 |
| EV-003 | Vulnerability state | Indexer `wazuh-states-vulnerabilities-*` | 20 Sep 2026 (UTC) | F-001 |
| EV-004 | Automated patching configuration and execution log | `/etc/apt/apt.conf.d/20auto-upgrades`, `systemctl is-enabled`, `/var/log/unattended-upgrades/unattended-upgrades.log`, `unattended-upgrade --dry-run --debug` | 20 Sep 2026 11:32–11:52 AEST | F-002 |
| EV-005 | Pending package updates | `apt update`; `apt list --upgradable` | 20 Sep 2026 (AEST) | F-002 |
| EV-006 | Authentication module inventory | `grep -rn 'pam_google_authenticator\|pam_u2f\|pam_oath' /etc/pam.d/` | 20 Sep 2026 (AEST) | F-003 |
| EV-007 | Deployment credential configuration | `~/wazuh-docker/single-node/docker-compose.yml`, `.env` | 20 Sep 2026 (AEST) | F-006 |
| EV-008 | Mapping engine consistency — baseline | `evals/runs/2026-09-19T163220Z-baseline.jsonl`; analysis in `evals/results/baseline/` | 19 Sep 2026 16:32 UTC | F-010 |
| EV-009 | Mapping engine consistency — temperature 0 | `evals/runs/2026-09-19T170617Z-temp0.jsonl`; analysis in `evals/results/temp0/` | 19 Sep 2026 17:06 UTC | F-010 |
| EV-010 | Backup state | Operator attestation | 20 Sep 2026 | F-007 |
| EV-011 | Out-of-scope SCA result (manager container) | Wazuh API `/sca/000` | 19 Sep 2026 15:25:23 UTC | Section 2, Section 8 |

---

## A.2 Evidence detail

### EV-001 — Agent inventory

```
GET /agents?select=id,name,status
```

One agent enrolled: id `001`, name `wsl-ubuntu`, status `active`. Agent
enrollment confirmed in `/var/ossec/logs/ossec.log` (`Valid key received`,
`Connected to the server ([127.0.0.1]:1514/tcp)`, 20 Sep 2026 11:34 AEST).

Agent `000` is the Wazuh manager itself and is excluded from scope — see EV-011.

### EV-002 — CIS Ubuntu 24.04 SCA results

```
GET /sca/001
GET /sca/001/checks/cis_ubuntu24-04?result=failed&limit=500
GET /sca/001/checks/cis_ubuntu24-04?result=not%20applicable&limit=500
```

Policy: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0, policy id
`cis_ubuntu24-04`, file hash
`66334fd2c0d5b66d59ed2cd8efd7ee0c2217c256e0cfbf8b78a5199514209f29`.

| Result | Count |
| --- | --- |
| Total checks | 279 |
| Pass | 89 |
| Fail | 125 |
| Not applicable | 65 |
| Reported score | 41 |

**Note on the reported score.** The 41 figure is derived as 89 / (89 + 125) and
excludes the 65 not-applicable checks from its denominator. It should not be
read as "41% compliant with CIS Ubuntu 24.04" — 23% of the benchmark returned no
determination at all. See Section 8.

**Provenance of the policy file.** The policy shipped with Wazuh 4.10.0 covers
Ubuntu 22.04 only and was skipped by the version check on this 24.04 host
(`Skipping policy 'cis_ubuntu22-04.yml': 'Check Ubuntu version.'`). The 24.04
policy was obtained from the Wazuh source repository at tag v4.13.0 and placed
in the agent ruleset directory. Policy file version (4.13.0) therefore differs
from agent version (4.10.0). This is recorded as a limitation in Section 8.

### EV-003 — Vulnerability state

```
GET https://localhost:9200/wazuh-states-vulnerabilities-*/_count
GET https://localhost:9200/wazuh-states-vulnerabilities-*/_search
    (aggregation on vulnerability.severity; filtered extract of High findings)
```

26 records, all with `agent.id: 001`, `agent.name: wsl-ubuntu`.

| Severity | Count |
| --- | --- |
| High | 11 |
| Medium | 13 |
| Low | 2 |
| Critical | 0 |

High-severity findings, with publication dates as reported by the feed:

| CVE | Package | CVSS base | Published |
| --- | --- | --- | --- |
| CVE-2024-6345 | setuptools | 8.8 | 2024-07-15 |
| CVE-2024-41671 | Twisted | 8.3 | 2024-07-29 |
| CVE-2024-5138 | snapd | 8.1 | 2024-05-31 |
| CVE-2024-41996 | openssl | 7.5 | 2024-08-26 |
| CVE-2024-39689 | certifi | 7.5 | 2024-07-05 |
| CVE-2024-3651 | idna | 7.5 | 2024-07-07 |
| CVE-2023-50782 | cryptography | 7.5 | 2024-02-05 |
| CVE-2024-26130 | cryptography | 7.5 | 2024-02-21 |
| CVE-2017-13716 | binutils | 7.1 | 2017-08-28 |

Two `cryptography` CVEs appear against two distinct package instances, giving 11
records from 9 distinct CVEs.

**Note.** The index is named `wazuh-states-vulnerabilities-wazuh.manager` after
the manager node, not the scanned host. The `agent.name` field confirms the
findings belong to `wsl-ubuntu`.

### EV-004 — Automated patching configuration and execution

`/etc/apt/apt.conf.d/20auto-upgrades`:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

`systemctl is-enabled unattended-upgrades` → `enabled`.

Execution log, 20 Sep 2026 01:32:09 and 01:42:17 (log timestamps):

```
Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security,
  o=UbuntuESMApps,a=noble-apps-security, o=UbuntuESM,a=noble-infra-security
No packages found that can be upgraded unattended and no pending auto-removals
```

`unattended-upgrade --dry-run --debug` confirms pin priority -32768 applied to
`noble-updates` (main, universe, restricted, multiverse), `noble-backports`, and
the Docker CE repository, excluding them from automated upgrade. Result:
`left to upgrade set()`, `InstCount=0`.

No `pip`, `snap` or container image update mechanism is referenced anywhere in
the configuration.

### EV-005 — Pending package updates

`apt update` followed by `apt list --upgradable`: 174 packages available.
Sampled entries confirm origin `noble-updates`:

```
apparmor/noble-updates 4.0.1really4.0.1-0ubuntu0.24.04.7 [upgradable from: ...5]
apport/noble-updates 2.28.3-0ubuntu0.1 [upgradable from: 2.28.1-0ubuntu3.8]
base-files/noble-updates 13ubuntu10.5 [upgradable from: 13ubuntu10.4]
```

`ubuntu-security-status`: 621 packages installed — 600 Main/Restricted, 13
Universe/Multiverse, 7 third-party, 1 no longer available for download. System
not attached to an Ubuntu Pro subscription; 2 pending ESM security updates for
Universe/Multiverse packages are consequently unavailable.

**Analytical note.** An initial count using `grep -c security` against the
upgradable list returned 122 and was discarded. That figure matched the string
"security" within package *version* identifiers, not the `noble-security`
pocket, and would have supported the incorrect conclusion that automated
patching was failing to apply available security updates. Origin fields were
checked directly instead. Recorded here because the discarded result, not the
final one, is the reason the conclusion in F-002 is stated as a coverage gap
rather than a control failure.

### EV-006 — Authentication module inventory

```
grep -rn "pam_google_authenticator\|pam_u2f\|pam_oath" /etc/pam.d/
→ no matches
```

Supporting CIS results from EV-002: checks 35671–35678 and 35687–35698
(`libpam-pwquality`, `pam_faillock`, `pam_pwquality`, `pam_pwhistory`, password
expiry, history, lockout) all fail.

### EV-007 — Deployment credential configuration

`~/wazuh-docker/single-node/docker-compose.yml` contains API credentials in
plain text for two services (manager and dashboard). `.env` is empty. Values
match the published defaults in the upstream `wazuh/wazuh-docker` repository.

Indexer credentials `admin` / default password were used successfully against
`https://localhost:9200` during this assessment, confirming they remain
unchanged.

**Credential values are deliberately not reproduced in this appendix.** They are
vendor defaults and are recoverable from the file itself by anyone with host
access; restating them here would put them in a document with a wider
distribution list than the file has.

### EV-008 / EV-009 — Mapping engine consistency evaluation

Method: 10 fixture alerts, 5 repetitions each, identical input, thresholds fixed
before the first run. Raw per-call output retained; analysis is reproducible
from the raw files without further API calls via `consistency_eval.py --analyse`.

| | EV-008 (baseline) | EV-009 (temp0) |
| --- | --- | --- |
| Temperature | 1.0 | 0.0 |
| Calls | 50 | 50 |
| Failed calls | 0 | 0 |
| HIGH-relevance agreement | 0.912 | 0.899 |
| Mean pairwise Jaccard | 0.813 | 0.820 |
| Relevance drift | 0.229 | 0.161 |
| Priority drift | 0.400 | 0.100 |
| Result against thresholds | FAIL | FAIL |

Per-framework relevance drift:

| Framework | EV-008 | EV-009 |
| --- | --- | --- |
| Essential Eight | 0.208 | 0.058 |
| NIST CSF v2 | 0.132 | 0.182 |
| ISO 27001 | 0.346 | 0.242 |

An earlier smoke run at K=1 recorded one failed call
(`2026-09-19T161440Z-smoke.jsonl`, alert_007), caused by the response exceeding
the configured `max_tokens` limit. The limit was raised and the failure did not
recur. It is noted because the pre-existing code reported the truncation as a
JSON parsing error, which would have concealed the cause; see Section 8.

### EV-010 — Backup state

Operator attestation, 20 September 2026: no backup process exists for the Wazuh
Docker volumes or the indexer data; no off-host copy is held; no restoration has
been tested.

Pipeline source code is held in a remote Git repository. This constitutes an
off-host copy of source only and does not extend to alert history, SCA results,
vulnerability state, Wazuh configuration, or agent enrollment keys.

**This entry rests on attestation rather than technical evidence.** No artefact
can demonstrate the absence of a backup process. It is recorded as attestation
so that a reviewer can weight it accordingly.

### EV-011 — Out-of-scope SCA result

```
GET /sca/000
```

Retained to document why agent `000` is excluded from scope. The manager
container returned CIS Benchmark for Amazon Linux 2023 results: 183 checks, 50
pass, 45 fail, 88 not applicable, score 52. The 48% not-applicable rate reflects
a benchmark written for a full operating system being applied to a container.
These results are not assessed in Section 5.

---

## A.3 Evidence integrity

The following limitations apply to every entry above and should be read
alongside Section 8.

**Single location.** All evidence is held on the assessed host. There is no
off-host copy, no write-once storage, and no cryptographic sealing. The same
condition is reported as F-007. An assessment whose evidence base can be
destroyed or altered by compromise of the system under assessment carries
correspondingly limited assurance.

**No chain of custody.** Evidence was collected and is held by the same
individual who performed the assessment and operates the system. This is
unavoidable in a single-operator environment and is stated rather than
mitigated.

**Point in time.** Every entry is a snapshot. None of it evidences that a
control operated over any period — only its state at the moment of collection.
Demonstrating operating effectiveness requires repeated collection over time,
which this assessment does not provide.

**Automated collection only, except EV-010.** No process was observed in
operation, no personnel were interviewed, and no documentation was reviewed. A
control can be correctly configured and still not be followed in practice; that
distinction is outside what this evidence base can show.

---

# Appendix B — Control Crosswalk

## B.1 Purpose and caveat

This crosswalk supports cross-reference only. Maturity ratings in Section 4 are
determined solely against the ASD Essential Eight Maturity Model; no mapping
below contributes to a rating.

**Mappings are indicative, not authoritative.** The frameworks differ in
structure, granularity and intent — Essential Eight prescribes eight specific
mitigation strategies, NIST CSF v2 organises outcomes across six functions, and
ISO/IEC 27001:2022 Annex A enumerates 93 controls. A one-to-one correspondence
does not exist in either direction, and treating these mappings as equivalences
would overstate what compliance with one framework says about another.

Where a mapping is contested or partial, that is noted rather than smoothed
over.

## B.2 Essential Eight ↔ NIST CSF v2 ↔ ISO/IEC 27001:2022

| E8 | Strategy | NIST CSF v2 | ISO 27001:2022 Annex A | Note |
| --- | --- | --- | --- | --- |
| E8-1 | Application Control | PR.PS-01, PR.PS-05 | A.8.19, A.8.7 | ISO has no direct allowlisting control; A.8.19 governs software installation, which is adjacent but narrower |
| E8-2 | Patch Applications | ID.RA-01, PR.PS-02 | A.8.8 | Closest alignment of any strategy across all three frameworks |
| E8-3 | Configure MS Office Macro Settings | PR.PS-05 | A.8.7, A.8.19 | No framework outside E8 addresses macros specifically; mapping is by category |
| E8-4 | User Application Hardening | PR.PS-01 | A.8.7, A.8.9 | Partial. ISO A.8.9 covers configuration management broadly, not application hardening as E8 defines it |
| E8-5 | Restrict Administrative Privileges | PR.AA-05 | A.8.2, A.5.15, A.5.18 | A.8.2 (privileged access rights) is the primary mapping |
| E8-6 | Patch Operating Systems | ID.RA-01, PR.PS-02 | A.8.8 | Shares controls with E8-2; neither NIST nor ISO separates OS from application patching |
| E8-7 | Multi-Factor Authentication | PR.AA-03 | A.8.5, A.5.17 | A.8.5 (secure authentication) covers MFA without mandating it |
| E8-8 | Regular Backups | PR.DS-11, RC.RP-01 | A.8.13, A.5.29, A.5.30 | A.8.13 is direct; A.5.29 and A.5.30 cover the continuity context |

**Observation on the crosswalk itself.** E8-2 and E8-6 map to the same controls
in both other frameworks, and E8-3 and E8-4 have no dedicated counterpart in
either. This is not a defect in the mapping. It reflects that Essential Eight is
a prioritised list of specific mitigations chosen for the Australian threat
environment, while NIST CSF and ISO 27001 are general management frameworks.
Organisations satisfying either of the latter may still have significant
Essential Eight gaps, and this assessment's results illustrate the point: the
host would pass a number of ISO A.8.8 configuration expectations while sitting
at ML0 for both patching strategies.

## B.3 AI-specific controls

The compliance mapping engine assessed in F-010 is an LLM application and falls
outside all three frameworks above. The following references are provided for
the findings that concern it.

| Concern | Finding | OWASP Top 10 for LLM Applications | ISO 27001:2022 |
| --- | --- | --- | --- |
| Prompt injection via attacker-controlled threat intelligence fields | F-010, fixture `alert_010` | LLM01 Prompt Injection | A.5.23, A.8.29 |
| Unverified model output used as assessment input | F-010 | LLM05 Improper Output Handling, LLM09 Misinformation | A.8.29 |
| Dependence on a third-party model provider with no supplier assurance | Section 8.8 | LLM03 Supply Chain | A.5.19, A.5.21 |
| Engine holds an API credential on an endpoint with known vulnerabilities | F-001, F-006 | LLM02 Sensitive Information Disclosure | A.5.17, A.8.24 |

**On the injection vector specifically.** The engine consumes AbuseIPDB
enrichment data, of which `domain`, `hostnames`, `isp` and `usage_type` derive
from reverse DNS and WHOIS records that an attacker controls for their own
infrastructure. This is a path by which an attacker influences a governance
control's reasoning via a trusted third-party feed — distinct from, and less
visible than, injection through log content. Testing showed the engine resisted
it (F-010), but the vector remains and warrants retesting whenever prompts or
enrichment sources change.

**MITRE ATLAS.** ATLAS technique identifiers are deliberately omitted. The
matrix is revised more frequently than these framework mappings, and citing an
identifier that has since been renumbered would be worse than citing none.
Anyone extending this crosswalk should map against the current published matrix
rather than relying on identifiers reproduced here.

---

# Appendix C — Risk Rating Matrix

## C.1 Likelihood

Assessed for the environment characterised in Section 2.6 — a single-operator
development endpoint with no inbound internet exposure.

| Level | Definition |
| --- | --- |
| **High** | Exploitation requires no specific conditions beyond access the threat actor would ordinarily obtain, or the condition is already being exploited elsewhere at scale |
| **Medium** | Exploitation requires the actor to first obtain access or conditions that are plausible but not automatic |
| **Low** | Exploitation requires conditions that do not currently exist in this environment, or a chain of prior compromises |

## C.2 Consequence

| Level | Definition |
| --- | --- |
| **High** | Code execution on the host; compromise of the security monitoring platform; destruction of the assessment evidence base |
| **Medium** | Privilege escalation; loss of ability to detect or investigate; unreliable governance output acted upon as if reliable |
| **Low** | Reduced defence in depth with no immediate path to impact |

## C.3 Matrix

| | Consequence: Low | Consequence: Medium | Consequence: High |
| --- | --- | --- | --- |
| **Likelihood: High** | Low | Medium | **High** |
| **Likelihood: Medium** | Low | Medium | **High** |
| **Likelihood: Low** | Low | Low | Medium |

## C.4 Ratings applied

| Finding | Likelihood | Consequence | Rating |
| --- | --- | --- | --- |
| F-001 Unpatched High vulnerabilities | Medium | High | **High** |
| F-002 Patching coverage gap | High | High | **High** |
| F-007 No backups | Medium | High | **High** |
| F-003 No MFA | Low | Medium | Medium ¹ |
| F-004 No application control | Medium | Medium | Medium |
| F-005 Privilege controls partial | Medium | Medium | Medium |
| F-006 Default credentials | Medium | Medium | Medium ² |
| F-009 No audit logging | Medium | Medium | Medium |
| F-010 Tooling not audit-reliable | High | Medium | Medium |
| F-008 No host firewall | Low | Low | Low |

¹ The matrix yields Low for this combination. Rated Medium by exception: the
absence of MFA is a categorical control gap under E8-7, and rating the sole
evidence for an ML0 determination as Low would understate it to a reader
scanning ratings alone. The exception is recorded rather than applied silently.

² Rated on the basis that the service is not reachable beyond the host. On a
network-reachable deployment, likelihood becomes High and the rating becomes
High.

## C.5 Note on rating exceptions

One finding (F-003) departs from the matrix. Departures are permitted where the
matrix produces a result that misrepresents the finding, but each must be stated
with its reasoning at the point of departure, as above.

A matrix that is overridden without record is not a matrix. If exceptions become
frequent, the definitions in C.1 and C.2 require revision rather than the
ratings requiring adjustment.
