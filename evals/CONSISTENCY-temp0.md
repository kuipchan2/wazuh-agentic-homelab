# Compliance Mapping Consistency Evaluation

- Source run: `2026-09-19T170617Z-temp0.jsonl`
- Label: temp0 | temperature: 0.0 | K: 5
- Generated: 2026-09-20T01:09:15.021324+00:00
- Alerts: 10 | Failed calls: 0
- **Result: FAIL**

## Thresholds (defined before the run)

| Criterion | Threshold | Observed | Result |
| --- | --- | --- | --- |
| HIGH-relevance agreement | 0.9 | 0.899 | FAIL |
| Mean pairwise Jaccard | 0.8 | 0.82 | PASS |
| Relevance drift (max) | 0.1 | 0.161 | FAIL |
| Priority drift (max) | 0.1 | 0.1 | PASS |

## Per framework

| Framework | Set agreement | Jaccard | HIGH agreement | Drift |
| --- | --- | --- | --- | --- |
| essential_eight | 0.9 | 0.927 | 1.0 | 0.058 |
| nist_csf_v2 | 0.78 | 0.788 | 0.85 | 0.182 |
| iso_27001 | 0.7 | 0.745 | 0.847 | 0.242 |

## Priority stability

- Mean modal stability: 0.96
- Alerts with any priority drift: 0.1

| Alert | Modal | Stability | Distribution |
| --- | --- | --- | --- |
| alert_001 | HIGH | 1.0 | {"HIGH": 5} |
| alert_002 | CRITICAL | 1.0 | {"CRITICAL": 5} |
| alert_003 | CRITICAL | 1.0 | {"CRITICAL": 5} |
| alert_004 | HIGH | 1.0 | {"HIGH": 5} |
| alert_005 | HIGH | 1.0 | {"HIGH": 5} |
| alert_006 | HIGH | 0.6 | {"CRITICAL": 2, "HIGH": 3} |
| alert_007 | CRITICAL | 1.0 | {"CRITICAL": 5} |
| alert_008 | HIGH | 1.0 | {"HIGH": 5} |
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
