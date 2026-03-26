import sys

sys.path.insert(0, ".")

from app.modules.detection.log_analyzer import detect_suspicious_ip

print("=" * 55)
print("IP INTELLIGENCE TEST SUITE")
print("=" * 55)

# Test 1: Private IP - should be LOW or skipped
lines1 = ["Connection from 192.168.1.100"] * 2
r1 = detect_suspicious_ip(lines1)
types1 = [f["type"] for f in r1]
t1 = all(f["risk"] in ["low", "medium"] for f in r1)
print(f"{'PASS' if t1 else 'FAIL'} T1: Private IP risk={[f['risk'] for f in r1] or 'skipped'}")

# Test 2: External IP with 5 failed logins - CRITICAL
lines2 = [
    "FAILED login attempt from 203.0.113.42"
] * 6
r2 = detect_suspicious_ip(lines2)
t2 = any(f["risk"] == "critical" and "203.0.113.42" in f["match"] for f in r2)
print(f"{'PASS' if t2 else 'FAIL'} T2: External IP brute force = {[f['type'] for f in r2]}")

# Test 3: External IP repeated 3 times - MEDIUM
lines3 = ["Request from 8.8.8.8 to /api"] * 3
r3 = detect_suspicious_ip(lines3)
t3 = any(f["risk"] in ["medium", "high"] for f in r3)
print(f"{'PASS' if t3 else 'FAIL'} T3: Repeated external IP = {[f['type'] for f in r3]}")

# Test 4: Internal IP with errors - MEDIUM
lines4 = [
    "ERROR from 10.0.0.5: connection refused",
    "ERROR from 10.0.0.5: timeout",
    "ERROR from 10.0.0.5: service unavailable",
]
r4 = detect_suspicious_ip(lines4)
t4 = any(f["type"] == "internal_ip_errors" for f in r4)
print(f"{'PASS' if t4 else 'FAIL'} T4: Internal IP errors = {[f['type'] for f in r4]}")

# Test 5: Loopback IP - should be LOW/skipped
lines5 = ["DEBUG from 127.0.0.1: health check ok"]
r5 = detect_suspicious_ip(lines5)
t5 = all(f["risk"] == "low" for f in r5) or len(r5) == 0
print(f"{'PASS' if t5 else 'FAIL'} T5: Loopback IP = {[f['risk'] for f in r5] or 'skipped'}")

# Test 6: External IP with attack pattern - CRITICAL
lines6 = [
    "POST /search from 45.33.32.156 payload=UNION SELECT * FROM users",
]
r6 = detect_suspicious_ip(lines6)
t6 = any(f["risk"] == "critical" for f in r6)
print(f"{'PASS' if t6 else 'FAIL'} T6: Attacker IP with SQLi = {[f['type'] for f in r6]}")

print("=" * 55)
all_ok = all([t1, t2, t3, t4, t5, t6])
print(f"RESULT: {'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}")
print("=" * 55)
