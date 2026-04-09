#!/usr/bin/env python3
"""
Wazuh AI Triage Agent v2 - Phase 4
改進版：加入 retry 邏輯、rate limiting、更穩定的錯誤處理
"""

import requests
import json
import time
import urllib3
from datetime import datetime, timezone
from anthropic import Anthropic, APIStatusError, APIConnectionError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 設定 ──────────────────────────────────────────
WAZUH_URL    = "https://localhost:55000"
WAZUH_USER   = "wazuh-wui"
WAZUH_PASS   = "MyS3cr37P450r.*-"
INDEXER_URL  = "https://localhost:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"
POLL_INTERVAL   = 30   # 每 30 秒掃描一次
MAX_RETRIES     = 3    # 最多重試 3 次
RETRY_DELAY     = 5    # 每次重試等 5 秒
API_DELAY       = 2    # 每個 alert 分析之間等 2 秒（避免 rate limit）
REPORT_FILE     = "triage_report_v2.jsonl"
MIN_LEVEL       = 3    # 只分析 level 3 以上的 alert
# ─────────────────────────────────────────────────

client = Anthropic()

def log(msg, level="INFO"):
    """統一的 log 格式"""
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "ℹ️ ", "OK": "✅", "WARN": "⚠️ ", "ERROR": "❌"}
    print(f"[{ts}] {icons.get(level, '')} {msg}")

def get_recent_alerts(size=20):
    """從 Indexer 取最新 alerts，只取 level 夠高的"""
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": "now-1h"}}},
                    {"range": {"rule.level": {"gte": MIN_LEVEL}}}
                ]
            }
        }
    }
    resp = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False,
        timeout=10
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]

def analyze_with_retry(alert):
    """分析 alert，失敗自動重試"""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    prompt = f"""你是一個 SOC analyst。分析以下 Wazuh security alert。

Alert:
- 規則 ID: {rule.get('id', 'N/A')}
- 描述: {rule.get('description', 'N/A')}
- 等級: {rule.get('level', 'N/A')} / 15
- MITRE: {rule.get('mitre', {}).get('id', 'N/A')}
- 主機: {agent.get('name', 'N/A')}
- 時間: {alert.get('timestamp', 'N/A')}
- 資料: {json.dumps(data, ensure_ascii=False)[:300]}

回傳 JSON 格式（只要 JSON，不要其他文字）:
{{
  "verdict": "TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_INVESTIGATION",
  "confidence": "HIGH / MEDIUM / LOW",
  "reason": "一句話解釋",
  "action": "建議行動"
}}"""

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}]
            )
            raw = message.content[0].text.strip()
            raw = raw.replace("```json", "").replace("```", "").strip()
            return json.loads(raw)

        except APIStatusError as e:
            if e.status_code == 529:
                # 暫時性：API 繁忙，等久一點再重試
                wait = RETRY_DELAY * attempt
                log(f"API 繁忙，{wait} 秒後重試 ({attempt}/{MAX_RETRIES})", "WARN")
                time.sleep(wait)
            elif e.status_code == 400:
                # 永久性：額度不足或請求格式錯誤，不重試
                log(f"API 錯誤 400: {e.message}", "ERROR")
                return None
            else:
                log(f"API 錯誤 {e.status_code}: {e.message}", "ERROR")
                time.sleep(RETRY_DELAY)

        except APIConnectionError:
            log(f"網路連線錯誤，{RETRY_DELAY} 秒後重試 ({attempt}/{MAX_RETRIES})", "WARN")
            time.sleep(RETRY_DELAY)

        except json.JSONDecodeError:
            log("LLM 回傳格式錯誤，重試中...", "WARN")
            time.sleep(RETRY_DELAY)

    log(f"已達最大重試次數，跳過此 alert", "ERROR")
    return None

def save_report(alert, analysis):
    """儲存分析結果"""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
    icons = {
        "TRUE_POSITIVE": "🔴",
        "FALSE_POSITIVE": "🟢",
        "NEEDS_INVESTIGATION": "🟡"
    }
    icon = icons.get(a.get("verdict"), "⚪")
    print(f"\n{'='*55}")
    print(f"{icon} [{a.get('verdict')}] confidence: {a.get('confidence')}")
    print(f"Rule {report['rule_id']}: {report['rule_desc'][:60]}")
    print(f"Host: {report['agent']} | Level: {report['level']}/15")
    print(f"Reason: {a.get('reason')}")
    print(f"Action: {a.get('action')}")
    print(f"{'='*55}")

def print_summary(results):
    """每輪掃描結束後印出統計"""
    if not results:
        return
    tp = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "TRUE_POSITIVE")
    fp = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "FALSE_POSITIVE")
    ni = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "NEEDS_INVESTIGATION")
    print(f"\n📊 本輪統計: 🔴 {tp} 真陽性 | 🟡 {ni} 需調查 | 🟢 {fp} 誤報")

def main():
    print("🤖 Wazuh AI Triage Agent v2 啟動")
    print(f"掃描間隔: {POLL_INTERVAL}s | 最小 Level: {MIN_LEVEL} | 最大重試: {MAX_RETRIES}次")
    print(f"報告存至: {REPORT_FILE}")
    print("按 Ctrl+C 停止\n")

    seen_ids = set()
    total_analyzed = 0
    session_start = datetime.now()

    while True:
        try:
            log(f"掃描中...")
            alerts = get_recent_alerts()
            new_alerts = [a for a in alerts if a.get("id") not in seen_ids]

            if not new_alerts:
                log("沒有新 alert")
            else:
                log(f"發現 {len(new_alerts)} 個新 alert，開始分析...")
                round_results = []

                for i, alert in enumerate(new_alerts, 1):
                    seen_ids.add(alert.get("id"))
                    rule_desc = alert.get("rule", {}).get("description", "")[:40]
                    log(f"分析 {i}/{len(new_alerts)}: {rule_desc}...")

                    analysis = analyze_with_retry(alert)
                    if analysis:
                        report = save_report(alert, analysis)
                        print_report(report)
                        round_results.append(report)
                        total_analyzed += 1

                    # Rate limiting：每個 alert 之間稍微等一下
                    if i < len(new_alerts):
                        time.sleep(API_DELAY)

                print_summary(round_results)
                elapsed = (datetime.now() - session_start).seconds // 60
                log(f"本次共分析 {total_analyzed} 個 alert（執行 {elapsed} 分鐘）", "OK")

        except KeyboardInterrupt:
            print(f"\n\n🛑 停止 Agent")
            print(f"總共分析: {total_analyzed} 個 alert")
            print(f"報告存至: {REPORT_FILE}")
            break
        except Exception as e:
            log(f"未預期錯誤: {e}", "ERROR")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
