#!/usr/bin/env python3
"""
Wazuh AI Triage Agent - Phase 3
自動讀取 Wazuh alerts，用 LLM 分析威脅等級
"""

import requests
import json
import time
import urllib3
from datetime import datetime
from anthropic import Anthropic

# 忽略 self-signed cert 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 設定 ──────────────────────────────────────────
WAZUH_URL  = "https://localhost:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "MyS3cr37P450r.*-"
INDEXER_URL  = "https://localhost:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"
POLL_INTERVAL = 30  # 每 30 秒檢查一次
REPORT_FILE = "triage_report.jsonl"
# ─────────────────────────────────────────────────

client = Anthropic()

def get_wazuh_token():
    """取得 Wazuh API JWT token"""
    resp = requests.post(
        f"{WAZUH_URL}/security/user/authenticate?raw=true",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False
    )
    return resp.text.strip()

def get_recent_alerts(size=10):
    """從 Indexer 取最新 alerts"""
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "timestamp": {
                    "gte": "now-1h"
                }
            }
        }
    }
    resp = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False
    )
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]

def analyze_alert(alert):
    """用 Claude 分析單個 alert"""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    prompt = f"""你是一個 SOC analyst。分析以下 Wazuh security alert，給出簡短評估。

Alert 資料:
- 規則 ID: {rule.get('id', 'N/A')}
- 規則描述: {rule.get('description', 'N/A')}
- 嚴重等級: {rule.get('level', 'N/A')} / 15
- MITRE ATT&CK: {rule.get('mitre', {}).get('id', 'N/A')}
- 來源主機: {agent.get('name', 'N/A')}
- 時間: {alert.get('timestamp', 'N/A')}
- 原始資料: {json.dumps(data, ensure_ascii=False)[:300]}

請用以下格式回答（JSON）:
{{
  "verdict": "TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_INVESTIGATION",
  "confidence": "HIGH / MEDIUM / LOW",
  "reason": "一句話解釋原因",
  "action": "建議採取的行動"
}}

只回傳 JSON，不要其他文字。"""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = message.content[0].text.strip()
    # 清理可能的 markdown
    raw = raw.replace("```json", "").replace("```", "").strip()
    return json.loads(raw)

def save_report(alert, analysis):
    """儲存分析結果到 JSONL 檔案"""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "alert_id": alert.get("id", "N/A"),
        "rule_id": alert.get("rule", {}).get("id", "N/A"),
        "rule_desc": alert.get("rule", {}).get("description", "N/A"),
        "level": alert.get("rule", {}).get("level", 0),
        "agent": alert.get("agent", {}).get("name", "N/A"),
        "analysis": analysis
    }
    with open(REPORT_FILE, "a") as f:
        f.write(json.dumps(report, ensure_ascii=False) + "\n")
    return report

def print_report(report):
    """印出分析結果"""
    a = report["analysis"]
    verdict_color = {
        "TRUE_POSITIVE": "🔴",
        "FALSE_POSITIVE": "🟢",
        "NEEDS_INVESTIGATION": "🟡"
    }.get(a.get("verdict"), "⚪")

    print(f"\n{'='*55}")
    print(f"{verdict_color} [{a.get('verdict')}] confidence: {a.get('confidence')}")
    print(f"Rule {report['rule_id']}: {report['rule_desc']}")
    print(f"Host: {report['agent']} | Level: {report['level']}/15")
    print(f"Reason: {a.get('reason')}")
    print(f"Action: {a.get('action')}")
    print(f"{'='*55}")

def main():
    print("🤖 Wazuh AI Triage Agent 啟動")
    print(f"每 {POLL_INTERVAL} 秒掃描一次，報告存至 {REPORT_FILE}")
    print("按 Ctrl+C 停止\n")

    seen_ids = set()

    while True:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 掃描中...")
            alerts = get_recent_alerts()

            new_alerts = [a for a in alerts if a.get("id") not in seen_ids]

            if not new_alerts:
                print("  → 沒有新 alert")
            else:
                print(f"  → 發現 {len(new_alerts)} 個新 alert，開始分析...")
                for alert in new_alerts:
                    seen_ids.add(alert.get("id"))
                    analysis = analyze_alert(alert)
                    report = save_report(alert, analysis)
                    print_report(report)

        except KeyboardInterrupt:
            print("\n\n停止 Agent。報告已存至", REPORT_FILE)
            break
        except Exception as e:
            print(f"  ⚠️  Error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
