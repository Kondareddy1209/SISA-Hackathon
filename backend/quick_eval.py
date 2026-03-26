#!/usr/bin/env python3
import requests
import time

BASE = "http://localhost:8000"
tests_passed = 0
tests_total = 0

def test(name, fn):
    global tests_passed, tests_total
    tests_total += 1
    try:
        result = fn()
        if result:
            print(f"[PASS] {name}")
            tests_passed += 1
        else:
            print(f"[FAIL] {name}")
    except Exception as e:
        print(f"[ERROR] {name}: {str(e)[:80]}")

print("=" * 60)
print("SISA HACKATHON - PLATFORM EVALUATION")
print("=" * 60)

# Health check
test("Health endpoint returns OK", lambda: (
    requests.get(f"{BASE}/health", timeout=10).json().get("status") == "ok"
))

# Patterns
test("Patterns endpoint exists", lambda: (
    len(requests.get(f"{BASE}/patterns", timeout=10).json().get("patterns", {})) > 0
))

# Spec log test
SPEC_LOG = """2026-03-10 10:00:01 INFO User login
email=admin@company.com
password=admin123
api_key=sk-prod-xyz
ERROR stack trace: NullPointerException at service.java:45"""

resp = requests.post(f"{BASE}/analyze", json={
    "input_type": "log",
    "content": SPEC_LOG,
    "options": {"mask": True, "block_high_risk": True, "log_analysis": True}
}, timeout=15).json()

test("Log: Email detected", lambda: any(f["type"]=="email" for f in resp.get("findings", [])))
test("Log: Password critical", lambda: any(f["type"]=="password" and f["risk"]=="critical" for f in resp.get("findings", [])))
test("Log: API Key detected", lambda: any(f["type"]=="api_key" for f in resp.get("findings", [])))
test("Log: Risk level HIGH", lambda: resp.get("risk_level") == "high")
test("Log: Action masked", lambda: resp.get("action") == "masked")

# Text input
TEXT = "email=admin@test.com password=hunter2 api_key=sk-prod-test123"
resp2 = requests.post(f"{BASE}/analyze", json={
    "input_type": "text",
    "content": TEXT,
    "options": {"mask": True}
}, timeout=10).json()

test("Text: Email detected", lambda: any(f["type"]=="email" for f in resp2.get("findings", [])))
test("Text: Password detected", lambda: any(f["type"]=="password" for f in resp2.get("findings", [])))

# SQL Injection
SQL = "SELECT * FROM users WHERE 1=1; DROP TABLE users; UNION SELECT password"
resp3 = requests.post(f"{BASE}/analyze", json={
    "input_type": "sql",
    "content": SQL,
    "options": {}
}, timeout=10).json()

test("SQL: Injection detected", lambda: any(f["type"]=="sql_injection" for f in resp3.get("findings", [])))

# API contract
test("Response has summary", lambda: "summary" in resp)
test("Response has findings", lambda: "findings" in resp)
test("Response has risk_level", lambda: "risk_level" in resp)
test("Response has action", lambda: "action" in resp)
test("Response has insights", lambda: "insights" in resp)

print("\n" + "=" * 60)
pct = (tests_passed / tests_total * 100) if tests_total > 0 else 0
grade = "EXCELLENT" if pct >= 90 else "GOOD" if pct >= 75 else "FAIR" if pct >= 60 else "NEEDS WORK"
print(f"FINAL SCORE: {tests_passed}/{tests_total} ({pct:.0f}%)")
print(f"GRADE: {grade}")
print("=" * 60)
