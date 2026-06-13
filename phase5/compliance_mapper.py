#!/usr/bin/env python3
"""
Wazuh Compliance Mapper - Phase 5
讀取 Phase 4 的 enrichment 報告，用 Claude API 自動 map 到三個 compliance framework：
  - ACSC Essential Eight
  - NIST CSF v2
  - ISO 27001:2022

用法:
  # 處理最近 10 筆 enriched alert
  python compliance_mapper.py

  # 處理指定數量
  python compliance_mapper.py --limit 5

  # 指定 input/output 路徑
  python compliance_mapper.py --input ../phase4/enrichment_report.jsonl --output compliance_report.jsonl
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

# ── 設定 ──────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 2000
DEFAULT_INPUT = "../phase4/enrichment_report.jsonl"
DEFAULT_OUTPUT = "compliance_report.jsonl"
SUMMARY_OUTPUT = "compliance_summary.json"
CONTROLS_FILE = Path(__file__).parent / "compliance_controls.json"
# ─────────────────────────────────────────────────

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "ℹ️ ", "OK": "✅", "WARN": "⚠️ ", "ERROR": "❌", "MAP": "🗺️ "}
    print(f"[{ts}] {icons.get(level, '')} {msg}")


def load_controls():
    """載入 compliance controls 參考資料"""
    if CONTROLS_FILE.exists():
        return json.loads(CONTROLS_FILE.read_text())
    log(f"找不到 {CONTROLS_FILE}，LLM 將只用 training knowledge", "WARN")
    return {}


def build_system_prompt(controls_ref: dict) -> str:
    """建立 Claude API 的 system prompt"""
    return """You are a cybersecurity GRC analyst performing compliance mapping for an Australian organisation.

Given an enriched Wazuh SIEM alert (with IP threat intelligence from AbuseIPDB), map it to relevant controls across three frameworks:

1. ACSC Essential Eight (E8-1 through E8-8)
2. NIST CSF v2 (subcategory codes like PR.AA, DE.CM)
3. ISO 27001:2022 (Annex A control numbers like A.8.8)

Rules:
- Only map to controls that are genuinely relevant. Do NOT force mappings.
- Provide 1-3 controls per framework.
- Relevance: HIGH = directly addresses the alert type, MEDIUM = related control area, LOW = tangential.
- Remediation must be actionable and specific to the alert, not generic advice.
- risk_summary should be written for a non-technical executive audience.

Return ONLY valid JSON (no markdown, no code fences, no explanation) matching this schema:
{
  "mappings": {
    "essential_eight": [
      {
        "control_id": "E8-X",
        "control_name": "...",
        "relevance": "HIGH|MEDIUM|LOW",
        "justification": "one sentence specific to this alert",
        "remediation": "specific actionable step"
      }
    ],
    "nist_csf_v2": [
      {
        "control_id": "XX.YY",
        "control_name": "...",
        "function": "GOVERN|IDENTIFY|PROTECT|DETECT|RESPOND|RECOVER",
        "relevance": "HIGH|MEDIUM|LOW",
        "justification": "...",
        "remediation": "..."
      }
    ],
    "iso_27001": [
      {
        "control_id": "A.X.Y",
        "control_name": "...",
        "relevance": "HIGH|MEDIUM|LOW",
        "justification": "...",
        "remediation": "..."
      }
    ]
  },
  "risk_summary": "One-paragraph executive summary of compliance implications",
  "priority": "CRITICAL|HIGH|MEDIUM|LOW"
}

REFERENCE CONTROLS:
""" + json.dumps(controls_ref, indent=2)


def map_alert_to_compliance(enriched_alert: dict, system_prompt: str) -> dict:
    """用 Claude API 將 enriched alert map 到 compliance controls"""
    try:
        import anthropic
    except ImportError:
        log("請安裝 anthropic: pip install anthropic", "ERROR")
        sys.exit(1)

    client = anthropic.Anthropic()

    # 整理 alert 資料給 LLM
    alert_summary = {
        "ip": enriched_alert.get("ip"),
        "rule_id": enriched_alert.get("rule_id"),
        "rule_description": enriched_alert.get("rule_desc"),
        "agent": enriched_alert.get("agent"),
        "ip_threat_intel": enriched_alert.get("ip_info", {}),
        "timestamp": enriched_alert.get("timestamp"),
    }

    response = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system_prompt,
        messages=[
            {
                "role": "user",
                "content": (
                    "Map this enriched Wazuh alert to compliance controls:\n\n"
                    + json.dumps(alert_summary, indent=2, ensure_ascii=False)
                ),
            }
        ],
    )

    result_text = response.content[0].text

    # 清理 markdown code fences（以防萬一）
    if result_text.startswith("```"):
        result_text = result_text.split("\n", 1)[1].rsplit("```", 1)[0]

    return json.loads(result_text)


def print_compliance(alert: dict, compliance: dict):
    """印出 compliance mapping 結果"""
    priority = compliance.get("priority", "UNKNOWN")
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon = icons.get(priority, "⚪")

    print(f"\n{'='*60}")
    print(f"{icon} Alert: {alert.get('rule_desc', 'N/A')[:55]}")
    print(f"   IP: {alert.get('ip', 'N/A')} | Priority: {priority}")
    print(f"{'─'*60}")

    mappings = compliance.get("mappings", {})

    # Essential Eight
    e8 = mappings.get("essential_eight", [])
    if e8:
        print("   🇦🇺 Essential Eight:")
        for ctrl in e8:
            rel = ctrl.get("relevance", "")
            rel_icon = "🔴" if rel == "HIGH" else "🟡" if rel == "MEDIUM" else "⚪"
            print(f"      {rel_icon} {ctrl['control_id']}: {ctrl['control_name']} [{rel}]")
            print(f"         → {ctrl.get('remediation', '')[:65]}")

    # NIST CSF v2
    nist = mappings.get("nist_csf_v2", [])
    if nist:
        print("   🌐 NIST CSF v2:")
        for ctrl in nist:
            print(f"      {ctrl['control_id']} ({ctrl.get('function', '')}): {ctrl['control_name']}")

    # ISO 27001
    iso = mappings.get("iso_27001", [])
    if iso:
        print("   📋 ISO 27001:")
        for ctrl in iso:
            print(f"      {ctrl['control_id']}: {ctrl['control_name']}")

    print(f"{'─'*60}")
    summary = compliance.get("risk_summary", "")
    if summary:
        # 每行最多 58 字元
        words = summary.split()
        line = "   📝 "
        for w in words:
            if len(line) + len(w) > 62:
                print(line)
                line = "      " + w + " "
            else:
                line += w + " "
        if line.strip():
            print(line)
    print(f"{'='*60}")


def generate_summary(results: list[dict]) -> dict:
    """彙總所有 compliance mapping 結果"""
    e8_hits = Counter()
    nist_hits = Counter()
    iso_hits = Counter()
    priority_dist = Counter()

    for r in results:
        compliance = r.get("compliance", {})
        mappings = compliance.get("mappings", {})

        for ctrl in mappings.get("essential_eight", []):
            e8_hits[ctrl["control_id"]] += 1
        for ctrl in mappings.get("nist_csf_v2", []):
            nist_hits[ctrl["control_id"]] += 1
        for ctrl in mappings.get("iso_27001", []):
            iso_hits[ctrl["control_id"]] += 1

        priority_dist[compliance.get("priority", "UNKNOWN")] += 1

    all_e8 = {f"E8-{i}" for i in range(1, 9)}
    triggered_e8 = set(e8_hits.keys())

    summary = {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "total_alerts_mapped": len(results),
        "essential_eight": {
            "controls_triggered": dict(e8_hits.most_common()),
            "controls_not_triggered": sorted(all_e8 - triggered_e8),
            "coverage_pct": round(len(triggered_e8) / 8 * 100, 1),
        },
        "nist_csf_v2": dict(nist_hits.most_common()),
        "iso_27001": dict(iso_hits.most_common()),
        "priority_distribution": dict(priority_dist),
    }

    return summary


def print_summary(summary: dict):
    """印出 compliance 彙總"""
    print(f"\n{'='*60}")
    print(f"📊 COMPLIANCE POSTURE SUMMARY")
    print(f"{'='*60}")
    print(f"   Alerts Mapped: {summary['total_alerts_mapped']}")

    e8 = summary["essential_eight"]
    print(f"\n   🇦🇺 Essential Eight Coverage: {e8['coverage_pct']}%")
    for ctrl, count in e8["controls_triggered"].items():
        print(f"      ✅ {ctrl}: {count} alerts")
    for ctrl in e8["controls_not_triggered"]:
        print(f"      ⬜ {ctrl}: no alerts (gap)")

    print(f"\n   Priority Distribution:")
    for p, count in summary["priority_distribution"].items():
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        print(f"      {icons.get(p, '⚪')} {p}: {count}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="Wazuh Compliance Mapper - Phase 5")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to enrichment_report.jsonl")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Path to save compliance report")
    parser.add_argument("--limit", type=int, default=10, help="Number of alerts to process")
    args = parser.parse_args()

    print("🗺️  Wazuh Compliance Mapper 啟動")
    print(f"   Input:  {args.input}")
    print(f"   Output: {args.output}")
    print(f"   Limit:  {args.limit} alerts\n")

    # 檢查 API key
    if not ANTHROPIC_API_KEY:
        log("請設定 ANTHROPIC_API_KEY 環境變數", "ERROR")
        log("  export ANTHROPIC_API_KEY=sk-ant-...", "ERROR")
        sys.exit(1)

    # 載入 controls 參考資料
    controls = load_controls()
    system_prompt = build_system_prompt(controls)
    log(f"載入 {len(controls)} 個 compliance frameworks", "OK")

    # 讀取 enrichment report
    input_path = Path(args.input)
    if not input_path.exists():
        log(f"找不到 {args.input}", "ERROR")
        log("請先執行 Phase 4 enrichment_agent.py 產生報告", "ERROR")
        sys.exit(1)

    lines = input_path.read_text().strip().split("\n")
    recent = lines[-args.limit:]
    log(f"讀取 {len(recent)} 筆 enriched alert（共 {len(lines)} 筆）")

    # 逐筆做 compliance mapping
    results = []
    for i, line in enumerate(recent, 1):
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            log(f"跳過格式錯誤的第 {i} 行", "WARN")
            continue

        ip = alert.get("ip", "unknown")
        rule = alert.get("rule_desc", "N/A")[:40]
        log(f"[{i}/{len(recent)}] Mapping: {ip} - {rule}...", "MAP")

        try:
            compliance = map_alert_to_compliance(alert, system_prompt)

            result = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "original_alert": alert,
                "compliance": compliance,
            }
            results.append(result)

            # 寫入報告
            with open(args.output, "a") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")

            print_compliance(alert, compliance)

        except json.JSONDecodeError as e:
            log(f"Claude API 返回格式錯誤: {e}", "ERROR")
        except Exception as e:
            log(f"Mapping 錯誤: {e}", "ERROR")

        # Rate limit 保護
        if i < len(recent):
            import time
            time.sleep(1)

    # 產生 summary
    if results:
        summary = generate_summary(results)
        Path(SUMMARY_OUTPUT).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False)
        )
        print_summary(summary)
        log(f"Compliance report 存至: {args.output}", "OK")
        log(f"Summary 存至: {SUMMARY_OUTPUT}", "OK")
    else:
        log("沒有成功 mapping 的 alert", "WARN")

    print(f"\n🏁 Compliance Mapper 完成！共處理 {len(results)} 筆 alert")


if __name__ == "__main__":
    main()
