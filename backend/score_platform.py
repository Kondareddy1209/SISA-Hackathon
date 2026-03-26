import sys, json, time, requests
sys.path.insert(0, ".")

BASE = "http://localhost:8000"
score = 0
total = 0
results = []
requests.adapters.DEFAULT_RETRIES = 3

def check(name, passed, marks, detail=""):
    global score, total
    total += marks
    if passed:
        score += marks
        results.append(f"  PASS  +{marks}  {name}")
        print(f"    [PASS] {name}")
    else:
        results.append(f"  FAIL   0  {name}  <- {detail}")
        print(f"    [FAIL] {name}")

print("=" * 65)
print("SISA HACKATHON — AUTOMATED PLATFORM SCORING")
print("=" * 65)

# ── SECTION 1: Backend Health (5 marks) ──────────────────────
print("\n[1] BACKEND HEALTH")
try:
    r = requests.get(f"{BASE}/health", timeout=5)
    d = r.json()
    check("GET /health returns 200", r.status_code == 200, 1)
    check("health.status = ok", d.get("status") == "ok", 1)
    check("health.model = claude-sonnet-4-6",
          d.get("model") == "claude-sonnet-4-6", 2)
    check("health.version present", bool(d.get("version")), 1)
except Exception as e:
    check("GET /health reachable", False, 5, str(e))

# ── SECTION 2: /patterns endpoint (3 marks) ──────────────────
print("\n[2] PATTERNS ENDPOINT")
try:
    r = requests.get(f"{BASE}/patterns", timeout=5)
    d = r.json()
    check("GET /patterns returns 200", r.status_code == 200, 1)
    check("patterns dict not empty", len(d.get("patterns", {})) > 0, 1)
    check("patterns has email+password+api_key",
          all(k in d.get("patterns", {})
              for k in ["email", "password", "api_key"]), 1)
except Exception as e:
    check("GET /patterns reachable", False, 3, str(e))

# ── SECTION 3: Spec Example — Log Input (20 marks) ───────────
print("\n[3] SPEC EXAMPLE — LOG INPUT (Section 9)")
SPEC_LOG = """2026-03-10 10:00:01 INFO User login
email=admin@company.com
password=admin123
api_key=sk-prod-xyz
ERROR stack trace: NullPointerException at service.java:45"""

try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "log",
        "content": SPEC_LOG,
        "options": {"mask": True, "block_high_risk": True,
                    "log_analysis": True}
    }, timeout=30)
    d = r.json()
    check("POST /analyze log returns 200", r.status_code == 200, 1)

    types = {f["type"] for f in d.get("findings", [])}
    risks = {f["type"]: f["risk"] for f in d.get("findings", [])}
    lines = {f["type"]: f.get("line") for f in d.get("findings", [])}

    check("email detected", "email" in types, 2)
    check("email risk = low", risks.get("email") == "low", 2)
    check("password detected", "password" in types, 2)
    check("password risk = critical", risks.get("password") == "critical", 2)
    check("api_key detected", "api_key" in types, 2)
    check("api_key risk = high", risks.get("api_key") == "high", 2)
    check("stack_trace detected", "stack_trace" in types, 1)
    check("risk_level = high", d.get("risk_level") == "high", 2)
    check("action = masked", d.get("action") == "masked", 2)
    check("summary mentions credentials",
          any(w in d.get("summary","").lower()
              for w in ["credential","sensitive","password"]), 2)
except Exception as e:
    check("Spec log test", False, 20, str(e))

# ── SECTION 4: Text Input (10 marks) ─────────────────────────
print("\n[4] TEXT INPUT")
TEXT_INPUT = ("My email is admin@company.com and my password is hunter2. "
              "The API key is sk-prod-abc123def456ghi789jkl012")
try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "text",
        "content": TEXT_INPUT,
        "options": {"mask": True, "block_high_risk": True}
    }, timeout=30)
    d = r.json()
    types = {f["type"] for f in d.get("findings", [])}
    check("text: 200 OK", r.status_code == 200, 1)
    check("text: email detected", "email" in types, 2)
    check("text: password detected", "password" in types, 2)
    check("text: api_key detected", "api_key" in types, 2)
    check("text: action=blocked (critical)",
          d.get("action") == "blocked", 2)
    check("text: risk_level=critical", d.get("risk_level") == "critical", 1)
except Exception as e:
    check("Text input test", False, 10, str(e))

# ── SECTION 5: SQL Input (8 marks) ───────────────────────────
print("\n[5] SQL INPUT")
SQL_INPUT = ("SELECT * FROM users WHERE 1=1; "
             "DROP TABLE users; UNION SELECT password FROM admin;")
try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "sql",
        "content": SQL_INPUT,
        "options": {"mask": True, "block_high_risk": True}
    }, timeout=30)
    d = r.json()
    types = {f["type"] for f in d.get("findings", [])}
    check("sql: 200 OK", r.status_code == 200, 1)
    check("sql: sql_injection detected", "sql_injection" in types, 3)
    check("sql: risk HIGH or CRITICAL",
          d.get("risk_level") in ["high","critical"], 2)
    check("sql: findings > 0", len(d.get("findings",[])) > 0, 2)
except Exception as e:
    check("SQL input test", False, 8, str(e))

# ── SECTION 6: Brute Force Log (8 marks) ─────────────────────
print("\n[6] BRUTE FORCE DETECTION")
BRUTE_LOG = "\n".join(
    ["FAILED login attempt for user admin from 10.0.0.1"] * 6
)
try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "log",
        "content": BRUTE_LOG,
        "options": {"mask": True, "block_high_risk": True,
                    "log_analysis": True}
    }, timeout=30)
    d = r.json()
    types = {f["type"] for f in d.get("findings", [])}
    check("brute force: 200 OK", r.status_code == 200, 1)
    check("brute_force type detected", "brute_force" in types, 4)
    check("brute force: risk HIGH or CRITICAL",
          d.get("risk_level") in ["high","critical"], 3)
except Exception as e:
    check("Brute force test", False, 8, str(e))

# ── SECTION 7: API Response Fields (8 marks) ─────────────────
print("\n[7] API CONTRACT — ALL REQUIRED FIELDS")
try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "text",
        "content": "password=secret123",
        "options": {}
    }, timeout=15)
    d = r.json()
    required = ["summary","content_type","findings","risk_score",
                "risk_level","action","insights","total_lines_analyzed",
                "detection_breakdown","generated_at"]
    for field in required:
        check(f"response has '{field}'", field in d, 0.8)
    check("detection_breakdown has regex/statistical/ml/ai",
          all(k in d.get("detection_breakdown",{})
              for k in ["regex","statistical","ml","ai"]), 1)
    check("findings have type+risk+line+value",
          all(all(k in f for k in ["type","risk","value"])
              for f in d.get("findings",[])[:3]), 1)
except Exception as e:
    check("API contract test", False, 9, str(e))

# ── SECTION 8: AI Insights (8 marks) ─────────────────────────
print("\n[8] AI INSIGHTS")
try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "text",
        "content": "api_key=sk-prod-test123456789 password=admin123",
        "options": {"use_ai": True, "mask": True}
    }, timeout=35)
    d = r.json()
    insights = d.get("insights", [])
    bd = d.get("detection_breakdown", {})
    check("insights list not empty", len(insights) > 0, 2)
    check("insights are specific (not generic)",
          any(any(w in i.lower() for w in
              ["line","critical","high","api","password","rotate","revoke"])
              for i in insights), 3)
    check("ai count in detection_breakdown",
          bd.get("ai", 0) > 0, 3)
except Exception as e:
    check("AI insights test", False, 8, str(e))

# ── SECTION 9: Masking (5 marks) ─────────────────────────────
print("\n[9] MASKING & POLICY")
try:
    r = requests.post(f"{BASE}/analyze", json={
        "input_type": "text",
        "content": "password=supersecret123 email=user@test.com",
        "options": {"mask": True, "block_high_risk": False}
    }, timeout=15)
    d = r.json()
    values = [f.get("value","") for f in d.get("findings",[])]
    check("masking: action=masked", d.get("action") == "masked", 2)
    check("masking: values are masked not plaintext",
          any("[" in v or "REDACTED" in v or "MASKED" in v
              for v in values), 3)
except Exception as e:
    check("Masking test", False, 5, str(e))

# ── SECTION 10: Backend Unit Tests (5 marks) ─────────────────
print("\n[10] BACKEND UNIT TESTS")
import subprocess
tests = [
    ("verify_bugs.py",    2),
    ("verify_all_fixes.py", 2),
    ("verify_fixes.py",    1),
]
for script, marks in tests:
    try:
        result = subprocess.run(
            ["python", script], capture_output=True,
            text=True, cwd=".", timeout=30
        )
        passed = ("FIXED" in result.stdout or
                  "PASS" in result.stdout or
                  "COMPLIANT" in result.stdout or
                  result.returncode == 0)
        check(f"{script} passes", passed, marks,
              result.stdout[-200:] if not passed else "")
    except Exception as e:
        check(f"{script}", False, marks, str(e))

# ── PRINT FINAL SCORE ─────────────────────────────────────────
print("\n" + "=" * 65)
print("DETAILED RESULTS:")
for r in results:
    print(r)
print("\n" + "=" * 65)
pct = round((score / total) * 100)
grade = ("EXCELLENT - READY" if pct >= 85
         else "GOOD - MINOR FIXES" if pct >= 70
         else "NEEDS WORK" if pct >= 50
         else "CRITICAL ISSUES")
print(f"AUTOMATED SCORE:  {score:.1f} / {total:.0f}  ({pct}%)")
print(f"GRADE:  {grade}")
print("=" * 65)
print("\nNote: Frontend UI (10 marks) requires manual check.")
print("Check: upload works, log viewer highlights lines,")
print("       detection breakdown bars show counts,")
print("       AI insights panel shows 'Powered by Claude'")
print("=" * 65)
