import re
from typing import Dict, List

PATTERNS = {
    "email": {
        "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "risk": "low",
        "category": "pii",
    },
    "password": {
        "regex": r"(?i)(password|passwd|pwd|pass)\s*(?:is\s+|=\s*|:\s*)\S+",
        "risk": "critical",
        "category": "credential",
    },
    "api_key": {
        "regex": r"(?i)(api_key|apikey|api-key|api_token)\s*[=:]\s*\S+|sk-[a-zA-Z0-9-]{15,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xoxb-[0-9]+-[a-zA-Z0-9]+",
        "risk": "high",
        "category": "credential",
    },
    "secret": {
        "regex": r"(?i)(secret|private[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*(?:=\s*|:\s*)\S+",
        "risk": "critical",
        "category": "credential",
    },
    "hardcoded_secret": {
        "regex": r"(?i)(auth[_\-]?secret|encryption[_\-]?key|signing[_\-]?key)\s*(?:=\s*|:\s*)\S+",
        "risk": "critical",
        "category": "credential",
    },
    "bearer_token": {
        "regex": r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{10,}=*",
        "risk": "high",
        "category": "credential",
    },
    "token": {
        "regex": r"(?i)(token|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token)\s*(?:=\s*|:\s*)\S+",
        "risk": "high",
        "category": "credential",
    },
    "xss_attempt": {
        "regex": r"(?i)(<script[\s\S]*?>[\s\S]*?</script>)|(<img[^>]+onerror\s*=)|(javascript\s*:)|(<iframe[^>]*>)|(onload\s*=|onclick\s*=|onmouseover\s*=)|(alert\s*\(|confirm\s*\(|prompt\s*\()",
        "risk": "high",
        "category": "injection",
    },
    "path_traversal": {
        "regex": r"(\.\./|\.\.\\){2,}|(\/etc\/passwd|\/etc\/shadow)|(\/windows\/system32)|(%2e%2e%2f|%2e%2e\/|\.\.%2f)",
        "risk": "high",
        "category": "injection",
    },
    "privilege_escalation": {
        "regex": r"(?i)(sudo\s+\w+.*command not allowed)|(sudo.*FAILED)|(su\s*:\s*authentication failure)|(www-data.*root)|(unauthorized.*privileged)|(escalat(e|ion).*privilege)",
        "risk": "critical",
        "category": "system",
    },
    "phone": {
        "regex": r"(\+?1?\s?)?(\(?\d{3}\)?[\s\-\.]?)(\d{3}[\s\-\.]?\d{4})",
        "risk": "low",
        "category": "pii",
    },
    "ssn": {
        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "risk": "critical",
        "category": "pii",
    },
    "stack_trace": {
        "regex": r"(?i)(exception|traceback|nullpointerexception|stack\s*trace|error\s+at\s+\w+\.\w+:\d+)",
        "risk": "medium",
        "category": "leak",
    },
    "sql_injection": {
        "regex": r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b",
        "risk": "high",
        "category": "injection",
    },
    "command_injection": {
        "regex": r"(;|\||&&|\$\(|`|>\s*/|<\s*/)",
        "risk": "high",
        "category": "injection",
    },
    "ip_address": {
        "regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "risk": "low",
        "category": "network",
    },
    "debug_mode": {
        "regex": r"(?i)(debug\s*=\s*true|debug\s+mode\s+enabled|verbose\s*=\s*true|stack\s*trace\s*enabled)",
        "risk": "medium",
        "category": "leak",
    },
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "risk": "high",
        "category": "credential",
    },
    "aws_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "risk": "critical",
        "category": "credential",
    },
    "credit_card": {
        "regex": r"\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b|\b(?:6011|65)[0-9]{12}\b",
        "risk": "critical",
        "category": "pii",
    },
    "private_key_block": {
        "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "risk": "critical",
        "category": "credential",
    },
    "connection_string": {
        "regex": r"(?i)(mongodb|mysql|postgresql|redis|mssql):\/\/[^\s\"']+:[^\s\"']+@[^\s\"']+",
        "risk": "critical",
        "category": "credential",
    },
}


def detect_all(text: str) -> List[Dict]:
    """
    Run all regex patterns against text line by line.
    Always returns line numbers. Works for ALL input types.
    """
    findings = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        seen_pattern_types = set()
        for pattern_name, pattern_data in PATTERNS.items():
            try:
                matches = re.finditer(
                    pattern_data["regex"], line, re.IGNORECASE
                )
                for match in matches:
                    if pattern_name in seen_pattern_types:
                        break
                    seen_pattern_types.add(pattern_name)
                    findings.append(
                        {
                            "type": pattern_name,
                            "risk": pattern_data["risk"],
                            "category": pattern_data["category"],
                            "match": match.group(),
                            "line": line_num,
                            "start": match.start(),
                            "end": match.end(),
                            "detection_method": "regex",
                        }
                    )
            except re.error:
                continue

    return findings


def get_all_patterns() -> Dict:
    """Return patterns metadata for /patterns endpoint."""
    return {
        name: {
            "risk": data["risk"],
            "category": data["category"],
        }
        for name, data in PATTERNS.items()
    }
