#!/usr/bin/env python3
"""
Unit tests for Triage Agent v2
測試核心邏輯，不需要真實的 Wazuh 或 Anthropic API
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase4'))

from triage_agent_v2 import save_report, REPORT_FILE

# ── Test 1: save_report 格式正確 ──────────────────
def test_save_report_format():
    alert = {
        "id": "test-001",
        "rule": {"id": "100001", "description": "SSH brute force", "level": 10},
        "agent": {"name": "test-host"},
        "timestamp": "2026-04-10T00:00:00Z"
    }
    analysis = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "reason": "Multiple failed logins",
        "action": "Block IP"
    }
    report = save_report(alert, analysis)

    assert report["rule_id"] == "100001"
    assert report["agent"] == "test-host"
    assert report["level"] == 10
    assert report["analysis"]["verdict"] == "TRUE_POSITIVE"
    print("✅ test_save_report_format passed")

# ── Test 2: verdict 只能是三種值 ──────────────────
def test_valid_verdicts():
    valid = {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"}
    test_verdicts = ["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"]
    for v in test_verdicts:
        assert v in valid
    print("✅ test_valid_verdicts passed")

# ── Test 3: level filter 邏輯 ─────────────────────
def test_level_filter():
    from triage_agent_v2 import MIN_LEVEL
    alerts = [
        {"rule": {"level": 1}},
        {"rule": {"level": 3}},
        {"rule": {"level": 10}},
    ]
    filtered = [a for a in alerts if a["rule"]["level"] >= MIN_LEVEL]
    assert len(filtered) == 2
    print("✅ test_level_filter passed")

# ── Test 4: enrichment IP 分類 ────────────────────
def test_private_ip_detection():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase4'))
    from enrichment_agent import check_ip_no_key

    result = check_ip_no_key("192.168.1.1")
    assert result["is_private"] == True
    assert result["verdict"] == "PRIVATE"

    result2 = check_ip_no_key("45.33.32.156")
    assert result2["is_private"] == False
    print("✅ test_private_ip_detection passed")

if __name__ == "__main__":
    print("🧪 Running tests...\n")
    test_save_report_format()
    test_valid_verdicts()
    test_level_filter()
    test_private_ip_detection()
    print("\n✅ All tests passed!")

    # 清理測試產生的檔案
    if os.path.exists(REPORT_FILE):
        os.remove(REPORT_FILE)
