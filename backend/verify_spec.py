import sys

sys.path.insert(0, ".")

print("=" * 65)
print("SPEC SECTION 9 - EXACT EXAMPLE VERIFICATION")
print("=" * 65)

SPEC_INPUT = """2026-03-10 10:00:01 INFO User login
email=admin@company.com
password=admin123
api_key=sk-prod-xyz
ERROR stack trace: NullPointerException at service.java:45"""

from app.modules.detection.log_analyzer import analyze_log
from app.modules.detection.statistical_detector import detect_statistical_anomalies
from app.modules.detection.ml_detector import detect_ml_anomalies
from app.modules.risk.risk_engine import (
    calculate_risk_score, get_risk_level, get_risk_summary
)
from app.modules.policy.policy_engine import determine_action, apply_masking

log_result = analyze_log(SPEC_INPUT)
findings = log_result["findings"]

stat_findings = detect_statistical_anomalies(SPEC_INPUT, "log")
ml_findings = detect_ml_anomalies(SPEC_INPUT, findings + stat_findings)
all_findings = findings + stat_findings + ml_findings

risk_score = calculate_risk_score(all_findings)
risk_level = get_risk_level(risk_score)
summary = get_risk_summary(all_findings, "log")

options = {"mask": True, "block_high_risk": True, "log_analysis": True}
action = determine_action(risk_level, options)

types_found = {f["type"] for f in all_findings}
risks_by_type = {}
for finding in all_findings:
    risks_by_type.setdefault(finding["type"], finding["risk"])

print(f"\nSpec Input Lines: 5")
print(f"Findings Found: {len(all_findings)}")
print(f"Types: {types_found}\n")

t1 = "email" in types_found
t2 = risks_by_type.get("email") == "low"
t3 = "password" in types_found
t4 = risks_by_type.get("password") == "critical"
t5 = "api_key" in types_found
t6 = risks_by_type.get("api_key") == "high"
t7 = "stack_trace" in types_found

print(f"{'PASS' if t1 else 'FAIL'} Email detected")
print(f"{'PASS' if t2 else 'FAIL'} Email = LOW risk (got: {risks_by_type.get('email')})")
print(f"{'PASS' if t3 else 'FAIL'} Password detected")
print(f"{'PASS' if t4 else 'FAIL'} Password = CRITICAL risk")
print(f"{'PASS' if t5 else 'FAIL'} API key detected")
print(f"{'PASS' if t6 else 'FAIL'} API key = HIGH risk")
print(f"{'PASS' if t7 else 'FAIL'} Stack trace detected")

email_line = next((f["line"] for f in all_findings if f["type"] == "email"), None)
pwd_line = next((f["line"] for f in all_findings if f["type"] == "password"), None)
api_line = next((f["line"] for f in all_findings if f["type"] == "api_key"), None)

t8 = email_line == 2
t9 = pwd_line == 3
t10 = api_line == 4

print(f"\n{'PASS' if t8 else 'FAIL'} Email at line 2 (got: {email_line})")
print(f"{'PASS' if t9 else 'FAIL'} Password at line 3 (got: {pwd_line})")
print(f"{'PASS' if t10 else 'FAIL'} API key at line 4 (got: {api_line})")

t11 = 8 <= risk_score <= 15
t12 = risk_level == "high"
t13 = action == "masked"
t14 = "credential" in summary.lower() or "sensitive" in summary.lower()

print(f"\n{'PASS' if t11 else 'FAIL'} Risk score ~12 (got: {risk_score})")
print(f"{'PASS' if t12 else 'FAIL'} Risk level = high (got: {risk_level})")
print(f"{'PASS' if t13 else 'FAIL'} Action = masked (got: {action})")
print(f"{'PASS' if t14 else 'FAIL'} Summary mentions credentials (got: '{summary}')")

print("\n" + "=" * 65)
all_pass = all([t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14])
print(f"SPEC COMPLIANCE: {'FULLY COMPLIANT' if all_pass else 'NEEDS FIXES'}")
print(f"Score: {sum([t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14])}/14 spec checks")
print("=" * 65)
