import sys

sys.path.insert(0, ".")

print("=" * 60)
print("DETECTION UPGRADE VERIFICATION")
print("=" * 60)

from app.modules.detection.regex_engine import detect_all
from app.modules.detection.statistical_detector import detect_statistical_anomalies
from app.modules.detection.ml_detector import detect_ml_anomalies

# Test 1: XSS detection
text1 = "<script>alert('XSS')</script> and <img onerror=alert(1)>"
f1 = detect_all(text1)
t1 = any(f["type"] == "xss_attempt" for f in f1)
print(f"{'PASS' if t1 else 'FAIL'} T1: XSS detection - {[f['type'] for f in f1]}")

# Test 2: Path traversal
text2 = "GET /admin/../../etc/passwd HTTP/1.1"
f2 = detect_all(text2)
t2 = any(f["type"] == "path_traversal" for f in f2)
print(f"{'PASS' if t2 else 'FAIL'} T2: Path traversal - {[f['type'] for f in f2]}")

# Test 3: SSN detection
text3 = "SSN: 123-45-6789"
f3 = detect_all(text3)
t3 = any(f["type"] == "ssn" for f in f3)
print(f"{'PASS' if t3 else 'FAIL'} T3: SSN detection - {[f['type'] for f in f3]}")

# Test 4: Private key block
text4 = "-----BEGIN RSA PRIVATE KEY-----\nabc123"
f4 = detect_all(text4)
t4 = any(f["type"] == "private_key_block" for f in f4)
print(f"{'PASS' if t4 else 'FAIL'} T4: Private key - {[f['type'] for f in f4]}")

# Test 5: High entropy (statistical)
text5 = "token=TESTAbC123xYz456QwEr789TyUi012OpLm"
f5 = detect_statistical_anomalies(text5, "text")
t5 = any(f["type"] == "high_entropy_string" for f in f5)
print(f"{'PASS' if t5 else 'FAIL'} T5: High entropy - {[f['type'] for f in f5]}")

# Test 6: ML correlation
text6 = "password=TESTPASS api_key=TESTKEY token=TESTTOKEN email=a@b.com"
f_existing = [{"risk": "critical"}, {"risk": "high"}, {"risk": "high"}]
f6 = detect_ml_anomalies(text6, f_existing)
t6 = len(f6) > 0
print(f"{'PASS' if t6 else 'FAIL'} T6: ML detection - {[f['type'] for f in f6]}")

# Test 7: Privilege escalation
from app.modules.detection.log_analyzer import detect_privilege_escalation

lines7 = ["sudo: www-data : command not allowed ; TTY=unknown ; USER=root"]
f7 = detect_privilege_escalation(lines7)
t7 = any(f["type"] == "privilege_escalation" for f in f7)
print(f"{'PASS' if t7 else 'FAIL'} T7: Privilege escalation - {[f['type'] for f in f7]}")

# Test 8: Connection string
text8 = "mongodb://admin:password123@db.company.com:27017/prod"
f8 = detect_all(text8)
t8 = any(f["type"] == "connection_string" for f in f8)
print(f"{'PASS' if t8 else 'FAIL'} T8: Connection string - {[f['type'] for f in f8]}")

print("=" * 60)
results = [t1, t2, t3, t4, t5, t6, t7, t8]
passed = sum(results)
print(f"RESULT: {passed}/8 tests passed")
if passed == 8:
    print("ALL UPGRADES VERIFIED - READY FOR SUBMISSION")
else:
    print("SOME UPGRADES NEED FIXING")
print("=" * 60)
