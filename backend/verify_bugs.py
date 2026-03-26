import sys

sys.path.insert(0, ".")

print("=" * 50)
print("BUG FIX VERIFICATION")
print("=" * 50)

from app.modules.detection.log_analyzer import detect_brute_force

lines = ["FAILED login attempt for user admin from 10.0.0.1"] * 6
bf = detect_brute_force(lines)
t1 = len(bf) > 0 and bf[0]["type"] == "brute_force"
print(f"{'PASS' if t1 else 'FAIL'} BUG2: Brute force - {bf[0]['type'] if bf else 'NOT DETECTED'}")

from app.modules.detection.regex_engine import detect_all

text = "My email is admin@company.com and my password is hunter2. The API key is sk-prod-abc123def456ghi789jkl012"
findings = detect_all(text)
types = [f["type"] for f in findings]
t2 = "api_key" in types
t3 = "password" in types
t4 = "email" in types
print(f"{'PASS' if t2 else 'FAIL'} BUG3a: api_key detected - types found: {types}")
print(f"{'PASS' if t3 else 'FAIL'} BUG3b: password detected")
print(f"{'PASS' if t4 else 'FAIL'} BUG3c: email detected")
print(f"Total findings: {len(findings)} (expected 3+)")

print("=" * 50)
all_ok = all([t1, t2, t3, t4])
print(f"RESULT: {'ALL BUGS FIXED' if all_ok else 'STILL HAS ISSUES'}")
print("=" * 50)
