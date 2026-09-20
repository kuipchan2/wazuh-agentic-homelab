# Phase 6 — Tool-Using Triage Agent

## Design specification

The current pipeline is a fixed sequence: every alert is enriched, then mapped,
in the same order, every time. Phase 6 replaces the triage stage with an agent
that decides for itself what information it needs, gathers it, and stops when it
has enough.

That single change is the boundary between a pipeline and an agent. Everything
else in this document exists because crossing that boundary makes the system
harder to trust, not easier.

---

## 1. Why constraints come before capability

The reliability work in Phase 5 measured a system that had no autonomy at all.
It still produced a 40% priority drift at default temperature, and a control
attribution bias that perfect consistency scores could not detect.

Under autonomy those problems compound rather than persist. A fixed pipeline
that drifts gives one wrong answer. An agent that drifts at step two gathers the
wrong evidence at step three and reasons from it at step four — and the final
output looks coherent, because it *is* coherent with respect to the wrong
evidence.

So the constraints below are not hardening applied after the fact. They are the
reason the agent is safe to build at all, and they are written first.

---

## 2. Capability scope

The agent may **read**. It may not **act**.

### Available tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `lookup_ip` | `ip` | AbuseIPDB reputation (existing Phase 4 function) |
| `get_related_alerts` | `rule_id`, `window_minutes` | Count and summary of similar alerts in window |
| `get_host_posture` | `agent_id` | SCA score, failed check count, open vulnerability counts by severity |
| `get_alert_context` | `alert_id`, `before`, `after` | Alerts from the same agent surrounding this one |
| `conclude` | `verdict`, `confidence`, `reasoning` | Terminal. Ends the loop. |
| `request_escalation` | `severity`, `reasoning` | Terminal. Records a recommendation. Does not notify anyone. |

`get_host_posture` is new and worth noting: it gives the agent access to the
configuration and vulnerability evidence collected during the Essential Eight
assessment. A brute-force alert against a host with no MFA and 11 unpatched High
vulnerabilities is a different finding from the same alert against a hardened
host. The agent can now make that distinction — and, more importantly, can be
observed making it or failing to.

### Deliberately excluded

| Not available | Why |
| --- | --- |
| `close_alert` | Closing is a decision with consequences and no undo. The agent recommends; a human closes. |
| `block_ip`, `isolate_host` | No enforcement actions. An agent that can act on a hallucinated verdict is a different risk class entirely. |
| Any write to Wazuh | The SIEM is the evidence base. An agent that can modify it can modify the record of its own errors. |
| Arbitrary shell or HTTP | Unbounded capability is unbounded blast radius. Every tool is a named, typed function. |

The exclusions are the design. Six tools, four of them read-only, two of them
terminal — that is the whole capability surface, and it is small enough to
reason about completely.

**Record the exclusions, not just the inclusions.** A future reviewer needs to
see that `close_alert` was considered and rejected, not that it was never
thought of.

---

## 3. Step budget

```python
MAX_TOOL_CALLS = 6
MAX_WALL_SECONDS = 120
```

On exceeding either, the loop terminates with `verdict: INCOMPLETE` and the
partial trail is retained.

**An incomplete result is a valid output, not an error.** The failure mode to
avoid is an agent that loops until something looks conclusive. Six calls is
enough to look up an IP, check related alerts, check host posture, and conclude
— with two spare. An agent needing more than that on a routine alert is
signalling that the alert is genuinely ambiguous, which is itself useful
information.

---

## 4. Audit trail

Every step is recorded. The trail is the deliverable, not a debug artefact.

```json
{
  "run_id": "20260921T0930Z-a1b2c3",
  "alert_id": "alert_001",
  "model": "claude-sonnet-4-6",
  "temperature": 0.0,
  "steps": [
    {
      "n": 1,
      "timestamp": "2026-09-21T09:30:01Z",
      "reasoning": "Source IP is external; reputation is the cheapest discriminator.",
      "tool": "lookup_ip",
      "args": {"ip": "198.51.100.24"},
      "result_summary": "abuseConfidenceScore=97, totalReports=1842",
      "latency_ms": 340
    }
  ],
  "outcome": {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "reasoning": "...",
    "terminated_by": "conclude",
    "tool_calls_used": 3
  }
}
```

Three requirements:

**Reasoning is captured per step, before the call.** Ask the model to state why
it is calling a tool as part of the call. A trail of tool invocations without
reasons tells you what happened but not whether it made sense.

**Results are summarised, not embedded whole.** Store a summary plus a hash of
the full response. Full AbuseIPDB payloads across five steps and ten alerts make
trails unreadable, and unreadable audit trails are not reviewed.

**The trail survives failure.** Write each step as it completes, not at the end.
A crashed run's partial trail is more useful than nothing, and the Phase 5
`max_tokens` incident is the precedent — a silent failure that looked like a
different problem entirely.

---

## 5. Loop structure

```python
def run_agent(alert, max_calls=MAX_TOOL_CALLS):
    messages = [{"role": "user", "content": format_alert(alert)}]
    trail = []

    for n in range(1, max_calls + 1):
        response = client.messages.create(
            model=MODEL,
            max_tokens=2000,
            temperature=0.0,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )

        if response.stop_reason == "max_tokens":
            return terminate(trail, "TRUNCATED", n)

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            # Model responded without calling a tool — it should have used
            # conclude(). Treat as a protocol violation, not a conclusion.
            return terminate(trail, "NO_TERMINAL_CALL", n)

        messages.append({"role": "assistant", "content": response.content})
        results = []

        for tu in tool_uses:
            if tu.name in TERMINAL_TOOLS:
                trail.append(record_step(n, tu, terminal=True))
                return finalise(trail, tu.input, n)

            result = dispatch(tu.name, tu.input)
            trail.append(record_step(n, tu, result))
            results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": summarise(result),
            })

        messages.append({"role": "user", "content": results})

    return terminate(trail, "BUDGET_EXHAUSTED", max_calls)
```

Two details that matter:

**A response with no tool call is a protocol violation, not an answer.** The
agent must terminate through `conclude` or `request_escalation`. Accepting free
text as a conclusion loses the structured verdict and confidence, and makes the
outcome unparseable for evaluation.

**Terminal tools return immediately** without dispatching. `conclude` is not a
function that does something; it is how the loop ends.

---

## 6. Prompt injection surface

The Phase 5 finding applies with more force here.

In the fixed pipeline, attacker-controlled threat-intelligence fields
(`domain`, `hostnames`, `isp` from reverse DNS and WHOIS) reached the model once.
Here they reach it mid-loop, where injected text can influence *which tools the
agent calls next* — not merely how it describes what it already has.

Carry the existing defence forward and extend it:

- Wrap every tool result in `<untrusted_data>`, not just the initial alert. Tool
  output is externally sourced by definition.
- Keep the system prompt's injection warning, and state explicitly that
  instructions appearing in tool results must be ignored and noted.
- Add a fixture that injects at **step two** rather than at input, so the test
  covers the mid-loop case that did not exist before.

An agent persuaded to stop investigating is as compromised as one persuaded to
reach a wrong verdict, and it looks cleaner in the trail.

---

## 7. Evaluation

The existing harness extends rather than being replaced. Same fixtures, same
K=5, same pre-set thresholds.

New metrics:

| Metric | Why |
| --- | --- |
| Tool-sequence consistency | Same alert, K runs — does the agent call the same tools in the same order? Jaccard over the tool multiset, plus exact-sequence agreement. |
| Step count variance | An agent using 2 calls on one run and 6 on the next for identical input has unstable stopping behaviour. |
| Verdict consistency | Existing metric, applied to `verdict` and `confidence`. |
| Termination distribution | How often each run ends via `conclude`, `request_escalation`, budget exhaustion, or protocol violation. |
| Reasoning–action coherence | Manual review: does the stated reason for each call match the tool actually invoked? Not automatable; sample it. |

**Set thresholds before the first run, as before.** Suggested opening values —
and expect to fail them, as Phase 5 did:

```python
AGENTIC_THRESHOLDS = {
    "tool_sequence_jaccard": 0.80,
    "verdict_consistency": 0.90,
    "max_step_count_stddev": 1.0,
    "protocol_violation_rate": 0.05,
}
```

**Run the fixed pipeline and the agent on the same fixtures.** The comparison is
the finding: if the agent's verdict consistency is materially worse than the
pipeline's, autonomy cost reliability, and that trade needs to be stated rather
than discovered later.

---

## 8. What this does and does not demonstrate

**Does.** Tool use, capability scoping with recorded exclusions, bounded
autonomy, per-step audit trail, and a measured comparison against the
non-agentic baseline.

**Does not.** Multi-agent coordination, planning over long horizons, memory
across alerts, or any action with real-world effect. Those are separate problems
and should not be claimed.

The honest description remains: an LLM-augmented pipeline, now with a bounded
tool-using agent at the triage stage, evaluated against the same reliability
thresholds as the stage it replaces.

---

## 9. Build order

| # | Step | Effort |
| --- | --- | --- |
| 1 | Define tool schemas; wrap existing Phase 4 functions as dispatchable tools | 2 hr |
| 2 | Implement `get_host_posture` against the SCA and vulnerability indices | 2 hr |
| 3 | Loop with step budget and audit trail | 3 hr |
| 4 | System prompt, including injection handling for tool results | 1 hr |
| 5 | Mid-loop injection fixture | 1 hr |
| 6 | Extend eval harness with the agentic metrics | 3 hr |
| 7 | Run both pipeline and agent on the same fixtures; write up the comparison | 2 hr |

Step 3 is the agent. Steps 1, 2, 4, 5, 6 and 7 are why it can be trusted, and
they are most of the work. That ratio is the point.
