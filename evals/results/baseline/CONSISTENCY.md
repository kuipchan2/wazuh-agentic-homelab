# Compliance Mapping Consistency Evaluation

- Source run: `2026-09-19T163220Z-baseline.jsonl`
- Label: baseline | temperature: 1.0 | K: 5
- Generated: 2026-09-20T01:13:10.152024+00:00
- Alerts: 10 | Failed calls: 0
- **Result: FAIL**

## Thresholds (defined before the run)

| Criterion | Threshold | Observed | Result |
| --- | --- | --- | --- |
| HIGH-relevance agreement | 0.9 | 0.912 | PASS |
| Mean pairwise Jaccard | 0.8 | 0.813 | PASS |
| Relevance drift (max) | 0.1 | 0.229 | FAIL |
| Priority drift (max) | 0.1 | 0.4 | FAIL |

## Per framework

| Framework | Set agreement | Jaccard | HIGH agreement | Drift |
| --- | --- | --- | --- | --- |
| essential_eight | 0.86 | 0.907 | 1.0 | 0.208 |
| nist_csf_v2 | 0.82 | 0.859 | 0.933 | 0.132 |
| iso_27001 | 0.62 | 0.672 | 0.802 | 0.346 |

## Priority stability

- Mean modal stability: 0.88
- Alerts with any priority drift: 0.4

| Alert | Modal | Stability | Distribution |
| --- | --- | --- | --- |
| alert_001 | HIGH | 1.0 | {"HIGH": 5} |
| alert_002 | CRITICAL | 1.0 | {"CRITICAL": 5} |
| alert_003 | CRITICAL | 1.0 | {"CRITICAL": 5} |
| alert_004 | HIGH | 0.6 | {"HIGH": 3, "CRITICAL": 2} |
| alert_005 | HIGH | 1.0 | {"HIGH": 5} |
| alert_006 | HIGH | 0.6 | {"HIGH": 3, "CRITICAL": 2} |
| alert_007 | CRITICAL | 0.8 | {"HIGH": 1, "CRITICAL": 4} |
| alert_008 | HIGH | 0.8 | {"HIGH": 4, "MEDIUM": 1} |
| alert_009 | LOW | 1.0 | {"LOW": 5} |
| alert_010 | HIGH | 1.0 | {"HIGH": 5} |

## Limitations

- Measures consistency, not correctness. A reliably incorrect mapping
  scores perfectly on every metric above.
- temperature=0 reduces but does not eliminate variation in LLM output.
- Fixture corpus is small and hand-selected; results do not generalise
  to the full alert population.
- Accuracy figures, where present, are a spot-check against hand-written
  ground truth and are not statistically representative.
- Scope is the mapping engine only. Nothing here evidences whether any
  Essential Eight control is implemented.
