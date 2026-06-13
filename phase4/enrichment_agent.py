#!/usr/bin/env python3
"""
Wazuh Enrichment Agent - Phase 4
自動讀取 triage 報告，對 TRUE_POSITIVE 的 IP 做威脅情報查詢
使用 AbuseIPDB（免費 API）
"""

import requests
import json
import time
import os
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 設定 ──────────────────────────────────────────
INDEXER_URL   = "https://localhost:9200"
INDEXER_USER  = "admin"
INDEXER_PASS  = "SecretPassword"
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
REPORT_FILE   = "enrichment_report.jsonl"
TRIAGE_FILE   = "../phase4/triage_report_v2.jsonl"
# ─────────────────────────────────────────────────

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "ℹ️ ", "OK": "✅", "WARN": "⚠️ ", "ERROR": "❌", "THREAT": "🚨"}
    print(f"[{ts}] {icons.get(level, '')} {msg}")

def get_ip_from_alert(alert_source):
    """從 alert 裡面抽取 IP"""
    # 嘗試不同的 IP 欄位
    candidates = [
        alert_source.get("data", {}).get("srcip"),
        alert_source.get("data", {}).get("src_ip"),
        alert_source.get("network", {}).get("source", {}).get("ip"),
        alert_source.get("agent", {}).get("ip"),
    ]
    for ip in candidates:
        if ip and ip not in ("127.0.0.1", "::1", "0.0.0.0"):
            return ip
    return None

def check_abuseipdb(ip):
    """查詢 AbuseIPDB"""
    if not ABUSEIPDB_KEY:
        return {"error": "No AbuseIPDB API key set"}

    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10
    )
    if resp.status_code == 200:
        d = resp.json().get("data", {})
        return {
            "ip": ip,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", "N/A"),
            "isp": d.get("isp", "N/A"),
            "is_tor": d.get("isTor", False),
            "last_reported": d.get("lastReportedAt", "N/A"),
            "verdict": "MALICIOUS" if d.get("abuseConfidenceScore", 0) > 50 else "CLEAN"
        }
    return {"error": f"API error {resp.status_code}"}

def check_ip_no_key(ip):
    """沒有 API key 時用基本資訊"""
    import socket
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "N/A"

    # 私有 IP 範圍檢查
    private_ranges = ["10.", "192.168.", "172.16.", "172.17.",
                      "172.18.", "172.19.", "172.20.", "127."]
    is_private = any(ip.startswith(r) for r in private_ranges)

    return {
        "ip": ip,
        "hostname": hostname,
        "is_private": is_private,
        "verdict": "PRIVATE" if is_private else "UNKNOWN",
        "note": "Install AbuseIPDB key for full threat intel"
    }

def enrich_ip(ip):
    """查詢 IP 威脅情報"""
    if ABUSEIPDB_KEY:
        return check_abuseipdb(ip)
    else:
        return check_ip_no_key(ip)

def get_actionable_alerts():
    """從 Indexer 取需要 enrichment 的 alert（有 IP 的）"""
    query = {
        "size": 20,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": "now-30d"}}},
                    {"range": {"rule.level": {"gte": 5}}}
                ],
                "should": [
                    {"exists": {"field": "data.srcip"}},
                    {"exists": {"field": "data.src_ip"}},
                    {"exists": {"field": "network.source.ip"}}
                ],
                "minimum_should_match": 1
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
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]

def print_enrichment(result):
    """印出 enrichment 結果"""
    ip_info = result.get("ip_info", {})
    verdict = ip_info.get("verdict", "UNKNOWN")
    icon = "🚨" if verdict == "MALICIOUS" else "✅" if verdict == "CLEAN" else "🔵"

    print(f"\n{'='*55}")
    print(f"{icon} IP: {ip_info.get('ip')} [{verdict}]")
    if "abuse_score" in ip_info:
        print(f"   Abuse Score: {ip_info['abuse_score']}% | Reports: {ip_info['total_reports']}")
        print(f"   Country: {ip_info['country']} | ISP: {ip_info['isp']}")
        print(f"   Tor Exit Node: {ip_info['is_tor']}")
    elif "is_private" in ip_info:
        print(f"   Private IP: {ip_info['is_private']} | Hostname: {ip_info.get('hostname')}")
    print(f"   Rule: {result.get('rule_desc', '')[:50]}")
    print(f"{'='*55}")

def main():
    print("🔍 Wazuh Enrichment Agent 啟動")
    if not ABUSEIPDB_KEY:
        log("沒有 ABUSEIPDB_KEY，使用基本 IP 分析模式", "WARN")
        log("申請免費 key: https://www.abuseipdb.com/register", "WARN")
    print("按 Ctrl+C 停止\n")

    seen_ips = set()

    while True:
        try:
            log("掃描需要 enrichment 的 alert...")
            alerts = get_actionable_alerts()

            if not alerts:
                log("沒有需要 enrichment 的 alert")
            else:
                log(f"找到 {len(alerts)} 個 alert，開始 IP enrichment...")
                for alert in alerts:
                    ip = get_ip_from_alert(alert)
                    if not ip or ip in seen_ips:
                        continue

                    seen_ips.add(ip)
                    log(f"查詢 IP: {ip}")
                    ip_info = enrich_ip(ip)

                    report = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "ip": ip,
                        "rule_id": alert.get("rule", {}).get("id"),
                        "rule_desc": alert.get("rule", {}).get("description"),
                        "agent": alert.get("agent", {}).get("name"),
                        "ip_info": ip_info
                    }

                    with open(REPORT_FILE, "a") as f:
                        f.write(json.dumps(report, ensure_ascii=False) + "\n")

                    print_enrichment(report)
                    time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n🛑 停止 Enrichment Agent")
            print(f"報告存至: {REPORT_FILE}")
            break
        except Exception as e:
            log(f"錯誤: {e}", "ERROR")

        time.sleep(30)

if __name__ == "__main__":
    main()
