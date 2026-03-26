import re
import sys

sys.path.insert(0, ".")

print("=" * 55)
print("FINAL POLISH VERIFICATION")
print("=" * 55)

from app.modules.detection.statistical_detector import (
    detect_high_entropy_strings,
    detect_statistical_anomalies,
)

# T1: SQL gets statistical findings
sql_text = "SELECT * FROM users WHERE 1=1; DROP TABLE users; UNION SELECT password FROM admin;"
f1 = detect_statistical_anomalies(sql_text, "sql")
t1 = any(f["type"] == "injection_keyword_density" for f in f1)
print(f"{'PASS' if t1 else 'FAIL'} T1: SQL statistical - {[f['type'] for f in f1]}")

# T2: Short log gets statistical findings
log_text = "2026-03-10 email=admin@company.com\npassword=admin123\napi_key=sk-prod-xyz"
f2 = detect_statistical_anomalies(log_text, "log")
t2 = len(f2) > 0
print(f"{'PASS' if t2 else 'FAIL'} T2: Short log statistical - {[f['type'] for f in f2]}")

# T3: High entropy has line number
text3 = "line1\ntoken=aB3kL9mN2pQ7rS4tU6vW1xY8zA5bC0dEfGhIjKlMnOpQrSt\nline3"
f3 = detect_high_entropy_strings(text3)
t3 = any(f.get("line") == 2 for f in f3)
print(f"{'PASS' if t3 else 'FAIL'} T3: Entropy line number - {[(f['type'], f.get('line')) for f in f3]}")

# T4: ML findings have line numbers
from app.modules.detection.ml_detector import detect_ml_anomalies

f4 = detect_ml_anomalies("password=x api_key=y secret=z token=t", [{"risk": "critical"}] * 3)
t4 = all(f.get("line") is not None for f in f4)
print(f"{'PASS' if t4 else 'FAIL'} T4: ML line numbers - {[(f['type'], f.get('line')) for f in f4]}")

# T5: Password regex doesn't false-match SQL
pattern = r"(?i)(password|passwd|pwd|pass)\s*(?:is\s+|=\s*|:\s*)\S+"
matches = re.findall(pattern, "UNION SELECT password FROM admin")
t5 = len(matches) == 0
print(f"{'PASS' if t5 else 'FAIL'} T5: Password no false match - matches={matches}")

# T6: Risk summary correct for connection string
from app.modules.risk.risk_engine import get_risk_summary

findings6 = [
    {"type": "connection_string", "risk": "critical"},
    {"type": "private_key_block", "risk": "critical"},
]
summary = get_risk_summary(findings6, "text")
t6 = "credential" in summary.lower()
print(f"{'PASS' if t6 else 'FAIL'} T6: Summary for connection string - '{summary}'")

print("=" * 55)
passed = sum([t1, t2, t3, t4, t5, t6])
print(f"RESULT: {passed}/6 final checks passed")
print("=" * 55)
