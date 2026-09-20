#!/usr/bin/env python3
"""
consistency_eval.py — reproducibility harness for the Phase 5 compliance mapper.

This is an EVALUATION HARNESS, not a unit test.
  - It makes real API calls (costs money, takes minutes).
  - Its results are inherently non-deterministic.
  - It must NOT gate CI. Run it manually or on a schedule.

Purpose: measure whether the same alert produces the same control mappings
across repeated runs. Consistency is a precondition for using the engine's
output as audit evidence.

NOTE: this measures CONSISTENCY, not CORRECTNESS. An engine that is
reliably wrong scores perfectly here. See accuracy_spotcheck() below.

Suggested sequence:
    python3 consistency_eval.py --temperature 1.0 --label baseline
    python3 consistency_eval.py --temperature 0.0 --label temp0
    python3 consistency_eval.py --analyse runs/<file>.jsonl

Place at evals/consistency_eval.py. Standard library only.
"""

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

# --------------------------------------------------------------------------
# CONFIG — set these BEFORE the first run, not after seeing results.
# Choosing thresholds to fit your numbers is not assessment, it's decoration.
# --------------------------------------------------------------------------

THRESHOLDS = {
    "high_relevance_agreement": 0.90,   # HIGH-relevance controls must be stable
    "overall_mean_jaccard": 0.80,
    "max_relevance_drift": 0.10,
    "max_priority_drift": 0.10,         # priority drives decisions — keep tight
}

FRAMEWORKS = ["essential_eight", "nist_csf_v2", "iso_27001"]


# ==========================================================================
# ADAPTER — wired to phase5/compliance_mapper.py
# ==========================================================================

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase5"))

_IMPORT_ERROR = None
try:
    from compliance_mapper import (  # noqa: E402
        load_controls, build_system_prompt, map_alert_to_compliance,
    )
    _SYSTEM_PROMPT = build_system_prompt(load_controls())
except ImportError as exc:  # allow --analyse without the mapper importable
    _SYSTEM_PROMPT = None
    _IMPORT_ERROR = exc


def call_mapper(alert: dict, temperature: float) -> dict:
    """One production-path call. The system prompt is built once so the eval
    exercises the same prompt the pipeline uses."""
    if _SYSTEM_PROMPT is None:
        raise RuntimeError(f"compliance_mapper not importable: {_IMPORT_ERROR}")
    return map_alert_to_compliance(alert, _SYSTEM_PROMPT, temperature)


def normalise(raw: dict) -> dict:
    """Flatten the mapper's output into a canonical shape for comparison.

        {
          "controls": {"essential_eight": {"E8-2": "HIGH"}, ...},
          "priority": "HIGH",
        }
    """
    controls = {fw: {} for fw in FRAMEWORKS}
    mappings = raw.get("mappings") or {}
    for fw in FRAMEWORKS:
        for e in mappings.get(fw) or []:
            if not isinstance(e, dict):
                continue
            cid = (e.get("control_id") or "").strip()
            if cid:
                controls[fw][cid] = (e.get("relevance") or "UNSPECIFIED").upper()
    return {
        "controls": controls,
        "priority": (raw.get("priority") or "UNSPECIFIED").upper(),
    }


# ==========================================================================
# METRICS
# ==========================================================================

def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def modal_set(sets: list) -> frozenset:
    return Counter(frozenset(s) for s in sets).most_common(1)[0][0]


def analyse_alert(runs: list) -> dict:
    """runs = K normalised outputs for one alert."""
    k = len(runs)
    result = {"k": k, "frameworks": {}}

    # Priority drift — a single field that directly drives triage decisions.
    # An alert that is sometimes CRITICAL and sometimes MEDIUM is a worse
    # problem than an unstable control set.
    priorities = [r["priority"] for r in runs]
    p_counts = Counter(priorities)
    modal_priority, modal_n = p_counts.most_common(1)[0]
    result["priority"] = {
        "modal": modal_priority,
        "stability": round(modal_n / k, 3),
        "distribution": dict(p_counts),
        "drifted": len(p_counts) > 1,
    }

    for fw in FRAMEWORKS:
        sets = [set(r["controls"][fw].keys()) for r in runs]
        modal = modal_set(sets)

        # 1. Set agreement — how often the exact modal set reappeared
        agreement = sum(1 for s in sets if frozenset(s) == modal) / k

        # 2. Mean pairwise Jaccard
        pairs = list(combinations(sets, 2))
        mean_jac = statistics.mean(jaccard(a, b) for a, b in pairs) if pairs else 1.0

        # 3. Per-control frequency — separates stable core from edge noise
        freq = Counter()
        for s in sets:
            freq.update(s)
        frequency = {cid: n / k for cid, n in freq.most_common()}
        stable_core = [c for c, f in frequency.items() if f == 1.0]
        edge_noise = [c for c, f in frequency.items() if f < 1.0]

        # 4. Relevance drift — did a control's HIGH/MEDIUM/LOW change?
        rel_by_control = defaultdict(set)
        for r in runs:
            for cid, rel in r["controls"][fw].items():
                rel_by_control[cid].add(rel)
        drifted = [c for c, rels in rel_by_control.items() if len(rels) > 1]
        drift_rate = len(drifted) / len(rel_by_control) if rel_by_control else 0.0

        high_controls = {
            cid for r in runs
            for cid, rel in r["controls"][fw].items() if rel == "HIGH"
        }
        high_agreement = (
            statistics.mean(frequency.get(c, 0.0) for c in high_controls)
            if high_controls else 1.0
        )

        result["frameworks"][fw] = {
            "set_agreement": round(agreement, 3),
            "mean_pairwise_jaccard": round(mean_jac, 3),
            "high_relevance_agreement": round(high_agreement, 3),
            "relevance_drift_rate": round(drift_rate, 3),
            "drifted_controls": sorted(drifted),
            "stable_core": sorted(stable_core),
            "edge_noise": sorted(edge_noise),
            "modal_set": sorted(modal),
        }

    return result


def aggregate(per_alert: dict) -> dict:
    agg = {"frameworks": {}, "overall": {}}
    for fw in FRAMEWORKS:
        vals = [a["frameworks"][fw] for a in per_alert.values()]
        agg["frameworks"][fw] = {
            "mean_set_agreement": round(
                statistics.mean(v["set_agreement"] for v in vals), 3),
            "mean_jaccard": round(
                statistics.mean(v["mean_pairwise_jaccard"] for v in vals), 3),
            "mean_high_relevance_agreement": round(
                statistics.mean(v["high_relevance_agreement"] for v in vals), 3),
            "mean_relevance_drift": round(
                statistics.mean(v["relevance_drift_rate"] for v in vals), 3),
        }

    all_fw = agg["frameworks"].values()
    priority_drift = (
        sum(1 for a in per_alert.values() if a["priority"]["drifted"])
        / len(per_alert) if per_alert else 0.0
    )
    agg["overall"] = {
        "mean_jaccard": round(statistics.mean(f["mean_jaccard"] for f in all_fw), 3),
        "mean_high_relevance_agreement": round(
            statistics.mean(f["mean_high_relevance_agreement"] for f in all_fw), 3),
        "mean_relevance_drift": round(
            statistics.mean(f["mean_relevance_drift"] for f in all_fw), 3),
        "priority_drift_rate": round(priority_drift, 3),
        "mean_priority_stability": round(
            statistics.mean(a["priority"]["stability"] for a in per_alert.values()), 3)
        if per_alert else 1.0,
    }

    o = agg["overall"]
    agg["thresholds"] = THRESHOLDS
    agg["pass"] = {
        "high_relevance_agreement":
            o["mean_high_relevance_agreement"] >= THRESHOLDS["high_relevance_agreement"],
        "overall_mean_jaccard":
            o["mean_jaccard"] >= THRESHOLDS["overall_mean_jaccard"],
        "max_relevance_drift":
            o["mean_relevance_drift"] <= THRESHOLDS["max_relevance_drift"],
        "max_priority_drift":
            o["priority_drift_rate"] <= THRESHOLDS["max_priority_drift"],
    }
    agg["pass"]["all"] = all(agg["pass"].values())
    return agg


# ==========================================================================
# ACCURACY SPOT-CHECK (separate concern — consistency != correctness)
# ==========================================================================

def accuracy_spotcheck(per_alert: dict, ground_truth_path: Path) -> dict:
    """Compare each alert's modal set against hand-written ground truth.

    fixtures/ground_truth.json:
        {"alert_001": {"essential_eight": ["E8-2"], "iso_27001": ["A.8.8"]}}

    Ten alerts is NOT statistically representative. Report it as a
    spot-check and say so in the Limitations section.
    """
    if not ground_truth_path.exists():
        return {"status": "skipped", "reason": "no ground truth file"}

    gt = json.loads(ground_truth_path.read_text())
    scores = defaultdict(list)
    for aid, res in per_alert.items():
        if aid not in gt:
            continue
        for fw in FRAMEWORKS:
            expected = set(gt[aid].get(fw, []))
            if not expected:
                continue
            actual = set(res["frameworks"][fw]["modal_set"])
            scores[fw].append(jaccard(expected, actual))

    return {
        "status": "completed",
        "n_alerts": len([a for a in per_alert if a in gt]),
        "caveat": "Spot-check only; sample too small to be representative.",
        "mean_jaccard_vs_ground_truth": {
            fw: round(statistics.mean(v), 3) for fw, v in scores.items()
        },
    }


# ==========================================================================
# RUN / REPORT
# ==========================================================================

def run(fixtures: Path, k: int, temperature: float, label: str,
        runs_dir: Path) -> Path:
    alerts = [json.loads(l) for l in fixtures.read_text().splitlines() if l.strip()]
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    out_path = runs_dir / f"{stamp}-{label}.jsonl"

    meta = {"_meta": True, "label": label, "temperature": temperature,
            "k": k, "fixtures": str(fixtures), "started": stamp}

    with out_path.open("w") as fh:
        fh.write(json.dumps(meta) + "\n")
        for alert in alerts:
            aid = alert.get("alert_id") or alert.get("id")
            for i in range(k):
                try:
                    raw = call_mapper(alert, temperature)
                    rec = {"alert_id": aid, "run": i, "ok": True, "raw": raw}
                except Exception as exc:  # failures are evidence too
                    rec = {"alert_id": aid, "run": i, "ok": False,
                           "error": f"{type(exc).__name__}: {exc}"}
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                print(f"  {aid} run {i + 1}/{k} "
                      f"{'ok' if rec['ok'] else 'FAILED'}", file=sys.stderr)

    print(f"\nRaw runs written to {out_path}", file=sys.stderr)
    return out_path


def analyse(run_path: Path, out_dir: Path) -> dict:
    by_alert = defaultdict(list)
    failures = 0
    meta = {}

    for line in run_path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("_meta"):
            meta = rec
            continue
        if rec.get("ok"):
            by_alert[rec["alert_id"]].append(normalise(rec["raw"]))
        else:
            failures += 1

    per_alert = {aid: analyse_alert(runs) for aid, runs in by_alert.items()}
    report = {
        "source_run": run_path.name,
        "run_meta": meta,
        "generated": datetime.now(timezone.utc).isoformat(),
        "n_alerts": len(per_alert),
        "failed_calls": failures,
        "per_alert": per_alert,
        **aggregate(per_alert),
    }
    report["accuracy_spotcheck"] = accuracy_spotcheck(
        per_alert, run_path.parent.parent / "fixtures" / "ground_truth.json"
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "consistency_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False))
    (out_dir / "CONSISTENCY.md").write_text(render_markdown(report))
    print(f"Report written to {out_dir}/consistency_report.json", file=sys.stderr)
    return report


def render_markdown(r: dict) -> str:
    verdict = "PASS" if r["pass"]["all"] else "FAIL"
    meta = r.get("run_meta", {})
    o = r["overall"]
    lines = [
        "# Compliance Mapping Consistency Evaluation",
        "",
        f"- Source run: `{r['source_run']}`",
        f"- Label: {meta.get('label', 'n/a')} | temperature: "
        f"{meta.get('temperature', 'n/a')} | K: {meta.get('k', 'n/a')}",
        f"- Generated: {r['generated']}",
        f"- Alerts: {r['n_alerts']} | Failed calls: {r['failed_calls']}",
        f"- **Result: {verdict}**",
        "",
        "## Thresholds (defined before the run)",
        "",
        "| Criterion | Threshold | Observed | Result |",
        "| --- | --- | --- | --- |",
    ]
    rows = [
        ("HIGH-relevance agreement", THRESHOLDS["high_relevance_agreement"],
         o["mean_high_relevance_agreement"], r["pass"]["high_relevance_agreement"]),
        ("Mean pairwise Jaccard", THRESHOLDS["overall_mean_jaccard"],
         o["mean_jaccard"], r["pass"]["overall_mean_jaccard"]),
        ("Relevance drift (max)", THRESHOLDS["max_relevance_drift"],
         o["mean_relevance_drift"], r["pass"]["max_relevance_drift"]),
        ("Priority drift (max)", THRESHOLDS["max_priority_drift"],
         o["priority_drift_rate"], r["pass"]["max_priority_drift"]),
    ]
    for name, thr, obs, ok in rows:
        lines.append(f"| {name} | {thr} | {obs} | {'PASS' if ok else 'FAIL'} |")

    lines += ["", "## Per framework", "",
              "| Framework | Set agreement | Jaccard | HIGH agreement | Drift |",
              "| --- | --- | --- | --- | --- |"]
    for fw, v in r["frameworks"].items():
        lines.append(
            f"| {fw} | {v['mean_set_agreement']} | {v['mean_jaccard']} | "
            f"{v['mean_high_relevance_agreement']} | {v['mean_relevance_drift']} |"
        )

    lines += ["", "## Priority stability", "",
              f"- Mean modal stability: {o['mean_priority_stability']}",
              f"- Alerts with any priority drift: {o['priority_drift_rate']}",
              "",
              "| Alert | Modal | Stability | Distribution |",
              "| --- | --- | --- | --- |"]
    for aid, a in r["per_alert"].items():
        p = a["priority"]
        lines.append(f"| {aid} | {p['modal']} | {p['stability']} | "
                     f"{json.dumps(p['distribution'])} |")

    lines += [
        "",
        "## Limitations",
        "",
        "- Measures consistency, not correctness. A reliably incorrect mapping",
        "  scores perfectly on every metric above.",
        "- temperature=0 reduces but does not eliminate variation in LLM output.",
        "- Fixture corpus is small and hand-selected; results do not generalise",
        "  to the full alert population.",
        "- Accuracy figures, where present, are a spot-check against hand-written",
        "  ground truth and are not statistically representative.",
        "- Scope is the mapping engine only. Nothing here evidences whether any",
        "  Essential Eight control is implemented.",
        "",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--fixtures", type=Path,
                   default=Path(__file__).parent / "fixtures" / "golden_alerts.jsonl")
    p.add_argument("-k", type=int, default=5, help="runs per alert")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--label", default="run", help="tag for this run file")
    p.add_argument("--runs-dir", type=Path, default=Path(__file__).parent / "runs")
    p.add_argument("--out-dir", type=Path, default=Path(__file__).parent)
    p.add_argument("--analyse", type=Path, help="analyse an existing run file only")
    args = p.parse_args()

    run_path = args.analyse or run(
        args.fixtures, args.k, args.temperature, args.label, args.runs_dir)
    report = analyse(run_path, args.out_dir)
    sys.exit(0 if report["pass"]["all"] else 1)


if __name__ == "__main__":
    main()
