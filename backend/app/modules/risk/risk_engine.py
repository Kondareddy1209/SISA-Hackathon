from typing import List, Dict

RISK_WEIGHTS = {
    "critical": 5,
    "high": 3,
    "medium": 2,
    "low": 1
}

RISK_THRESHOLDS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 0
}


def calculate_risk_score(findings: List[Dict]) -> int:
    """Calculate weighted risk score from all findings"""
    if not findings:
        return 0
    score = sum(
        RISK_WEIGHTS.get(f.get("risk", "low"), 1) 
        for f in findings
    )
    return min(score, 100)   # cap at 100


def get_risk_level(score: int) -> str:
    """Map score to risk level string"""
    if score >= RISK_THRESHOLDS["critical"]:
        return "critical"
    elif score >= RISK_THRESHOLDS["high"]:
        return "high"
    elif score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def get_risk_summary(findings: List[Dict], content_type: str) -> str:
    """Generate human-readable summary for API response"""
    if not findings:
        return f"No sensitive data detected in {content_type} input."

    types = {f.get("type") for f in findings}

    has_credentials = any(t in types for t in [
        "password", "secret", "hardcoded_secret",
        "connection_string", "private_key_block", "aws_key",
        "api_key", "bearer_token", "token", "jwt_token"
    ])
    has_errors = any(t in types for t in [
        "stack_trace", "debug_mode", "debug_leak"
    ])
    has_injection = any(t in types for t in [
        "sql_injection", "command_injection", "xss_attempt",
        "path_traversal", "privilege_escalation"
    ])
    has_attacks = any(t in types for t in [
        "brute_force", "attacker_ip", "malicious_ip",
        "repeated_failures", "failure_rate_spike"
    ])
    has_pii = any(t in types for t in [
        "email", "phone", "ssn", "credit_card"
    ])

    if content_type == "log":
        if has_credentials and has_errors:
            return "Log contains sensitive credentials and system errors"
        elif has_credentials and has_attacks:
            return "Log contains sensitive credentials and attack patterns"
        elif has_credentials:
            return "Log contains sensitive credentials"
        elif has_injection:
            return "Log contains injection attack patterns"
        elif has_attacks:
            return "Log contains attack patterns"
        elif has_errors:
            return "Log contains system error leaks"
        elif has_pii:
            return "Log contains PII data"
    else:
        label = f"{content_type.capitalize()} input contains"
        segments = []
        if has_credentials:
            segments.append("sensitive credentials")
        if has_injection:
            segments.append("injection patterns")
        if has_attacks:
            segments.append("attack patterns")
        if has_errors:
            segments.append("system information leaks")
        if has_pii:
            segments.append("PII data")

        if segments:
            return f"{label}: {', '.join(segments)}."

    return f"Security findings detected in {content_type} input."
