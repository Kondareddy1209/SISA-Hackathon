import sys

sys.path.insert(0, ".")
print("=" * 50)
print("VERIFICATION")
print("=" * 50)

from app.modules.detection.regex_engine import detect_all
from app.modules.detection.log_analyzer import detect_brute_force

# Test 1: brute force
lines = ["FAILED login attempt for user admin"] * 6
bf = detect_brute_force(lines)
t1 = len(bf) > 0
print(f"{'PASS' if t1 else 'FAIL'} Brute force detection")

# Test 2: api_key
findings = detect_all("The API key is sk-EXAMPLE000000000")
types = [f["type"] for f in findings]
t2 = "api_key" in types
print(f"{'PASS' if t2 else 'FAIL'} API key detection")

# Test 3: password
findings2 = detect_all("password=TESTPASS email=admin@test.com")
types2 = [f["type"] for f in findings2]
t3 = "password" in types2
print(f"{'PASS' if t3 else 'FAIL'} Password detection")

print("=" * 50)
all_ok = all([t1, t2, t3])
print(f"RESULT: {'ALL BUGS FIXED' if all_ok else 'ISSUES REMAIN'}")
print("=" * 50)
