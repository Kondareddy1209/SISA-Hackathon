#!/usr/bin/env python3
"""
SISA Hackathon - Automated Evaluation Script
Fast version with shorter timeouts and better error handling
"""
import requests
import subprocess
import sys
from pathlib import Path

BASE_URL = "http://localhost:8000"
TIMEOUT = 15  # Short timeout for faster feedback

class Scorer:
    def __init__(self):
        self.score = 0
        self.total = 0
        self.results = []
    
    def check(self, name, passed, marks=1, detail=""):
        self.total += marks
        if passed:
            self.score += marks
            self.results.append(f"  PASS  +{marks}  {name}")
            print(f"    [OK] {name}")
        else:
            self.results.append(f"  FAIL   0  {name}  <- {detail}")
            print(f"    [X]  {name}")
    
    def print_summary(self):
        pct = round((self.score / self.total) * 100) if self.total > 0 else 0
        grade = ("EXCELLENT" if pct >= 85 else "GOOD" if pct >= 70 else "NEEDS WORK" if pct >= 50 else "CRITICAL")
        print("\n" + "=" * 65)
        print("RESULTS SUMMARY:")
        for r in self.results[:10]:
            print(r)
        if len(self.results) > 10:
            print(f"  ... and {len(self.results)-10} more tests ...")
        print("\n" + "=" * 65)
        print(f"SCORE:  {self.score:.0f} / {self.total:.0f}  ({pct}%)")
        print(f"GRADE:  {grade}")
        print("=" * 65)

scorer = Scorer()
print("=" * 65)
print("SISA HACKATHON - AUTOMATED EVALUATION")
print("=" * 65)

# [1] BACKEND HEALTH
print("\n[1] BACKEND HEALTH")
try:
    r = requests.get(f"{BASE_URL}/health", timeout=TIMEOUT)
    d = r.json()
    scorer.check("Health 200 OK", r.status_code == 200)
    scorer.check("Status=ok", d.get("status") == "ok")
    scorer.check("Model configured", d.get("model") == "claude-sonnet-4-6", 2)
    scorer.check("Version present", bool(d.get("version")))
except Exception as e:
    scorer.check("Health endpoint", False, 5, str(e)[:50])

# [2] PATTERNS
print("\n[2] PATTERNS ENDPOINT")
try:
    r = requests.get(f"{BASE_URL}/patterns", timeout=TIMEOUT)
    d = r.json()
    scorer.check("Patterns 200 OK", r.status_code == 200)
    scorer.check("Patterns not empty", len(d.get("patterns", {})) > 0)
    has_all = all(k in d.get("patterns", {}) for k in ["email", "password", "api_key"])
    scorer.check("Has key patterns", has_all)
except Exception as e:
    scorer.check("Patterns endpoint", False, 3, str(e)[:50])

# [3] SPEC LOG INPUT
print("\n[3] SPEC LOG TEST")
SPEC_LOG = """2026-03-10 10:00:01 INFO User login
email=admin@company.com
password=TEST_ONLY
api_key=sk-EXAMPLE000000000
ERROR stack trace: NullPointerException at service.java:45"""

try:
    r = requests.post(f"{BASE_URL}/analyze", json={
        "input_type": "log",
        "content": SPEC_LOG,
        "options": {"mask": True, "block_high_risk": True, "log_analysis": True}
    }, timeout=TIMEOUT)
    d = r.json()
    scorer.check("Log analyze 200", r.status_code == 200)
    types = {f["type"] for f in d.get("findings", [])}
    scorer.check("Email detected", "email" in types)
    scorer.check("Password critical", any(f["type"]=="password" and f["risk"]=="critical" for f in d.get("findings",[])), 2)
    scorer.check("API Key detected", "api_key" in types)
    scorer.check("Risk level HIGH", d.get("risk_level") == "high", 2)
    scorer.check("Action masked", d.get("action") == "masked")
except Exception as e:
    scorer.check("Spec log test", False, 8, str(e)[:50])

# [4] TEXT INPUT  
print("\n[4] TEXT INPUT")
TEXT = "My email is admin@company.com password=TESTPASS api_key=sk-EXAMPLE000000000"
try:
    r = requests.post(f"{BASE_URL}/analyze", json={
        "input_type": "text",
        "content": TEXT,
        "options": {"mask": True}
    }, timeout=TIMEOUT)
    d = r.json()
    scorer.check("Text 200 OK", r.status_code == 200)
    types = {f["type"] for f in d.get("findings", [])}
    scorer.check("Email in text", "email" in types)
    scorer.check("Password in text", "password" in types)
    scorer.check("API key in text", "api_key" in types)
except Exception as e:
    scorer.check("Text test", False, 4, str(e)[:50])

# [5] SQL INJECTION
print("\n[5] SQL INJECTION")
SQL = "SELECT * FROM users; DROP TABLE users; UNION SELECT password FROM admin"
try:
    r = requests.post(f"{BASE_URL}/analyze", json={
        "input_type": "sql",
        "content": SQL,
        "options": {"mask": True}
    }, timeout=TIMEOUT)
    d = r.json()
    scorer.check("SQL 200 OK", r.status_code == 200)
    types = {f["type"] for f in d.get("findings", [])}
    scorer.check("SQL injection detected", "sql_injection" in types, 2)
    scorer.check("Risk HIGH/CRITICAL", d.get("risk_level") in ["high", "critical"])
except Exception as e:
    scorer.check("SQL injection test", False, 4, str(e)[:50])

# [6] API CONTRACT
print("\n[6] API CONTRACT FIELDS")
try:
    r = requests.post(f"{BASE_URL}/analyze", json={
        "input_type": "text",
        "content": "password=TESTPASS"
    }, timeout=TIMEOUT)
    d = r.json()
    required = ["summary", "findings", "risk_level", "action", "insights", "generated_at"]
    has_all = all(f in d for f in required)
    scorer.check("Has all fields", has_all, 2)
    scorer.check("Detection breakdown", "detection_breakdown" in d)
    scorer.check("Findings structured", len(d.get("findings",[])) > 0 and all("type" in f for f in d.get("findings",[])))
except Exception as e:
    scorer.check("API contract", False, 4, str(e)[:50])

# [7] AI INSIGHTS
print("\n[7] AI INSIGHTS")
try:
    r = requests.post(f"{BASE_URL}/analyze", json={
        "input_type": "text",
        "content": "password=TEST_ONLY api_key=sk-EXAMPLE000000000",
        "options": {"use_ai": True, "mask": True}
    }, timeout=20)
    d = r.json()
    scorer.check("AI insights generated", len(d.get("insights",[])) > 0, 2)
    bd = d.get("detection_breakdown", {})
    scorer.check("AI detection count", bd.get("ai", 0) > 0)
except Exception as e:
    scorer.check("AI insights test", False, 3, str(e)[:50])

# [8] MASKING
print("\n[8] MASKING")
try:
    r = requests.post(f"{BASE_URL}/analyze", json={
        "input_type": "text",
        "content": "password=EXAMPLEPASS email=user@test.com",
        "options": {"mask": True}
    }, timeout=TIMEOUT)
    d = r.json()
    values = [f.get("value","") for f in d.get("findings",[])]
    is_masked = any("[" in v or "REDACTED" in v or "***" in v for v in values)
    scorer.check("Values masked", is_masked, 2)
except Exception as e:
    scorer.check("Masking test", False, 2, str(e)[:50])

scorer.print_summary()
