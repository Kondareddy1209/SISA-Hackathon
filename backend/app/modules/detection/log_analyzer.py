import ipaddress
import re
from collections import defaultdict
from typing import Dict, List

from app.modules.detection.regex_engine import detect_all

PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def parse_log_lines(text: str) -> List[str]:
    """Handle both Unix and Windows line endings."""
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def detect_brute_force(lines: List[str]) -> List[Dict]:
    """Detect 5+ consecutive failed login attempts."""
    findings = []
    failed_count = 0
    first_line = 0

    failed_keywords = [
        "failed login",
        "login failed",
        "failed attempt",
        "authentication failed",
        "invalid password",
        "invalid credentials",
        "auth failed",
        "incorrect password",
    ]

    for index, line in enumerate(lines):
        line_lower = line.lower().strip()

        if any(keyword in line_lower for keyword in failed_keywords):
            if failed_count == 0:
                first_line = index + 1
            failed_count += 1
        else:
            if failed_count >= 5:
                findings.append(
                    {
                        "type": "brute_force",
                        "risk": "high",
                        "category": "statistical",
                        "line": first_line,
                        "match": (
                            f"Brute force: {failed_count} consecutive failed logins "
                            f"starting at line {first_line}"
                        ),
                        "value": "[ANOMALY: BRUTE FORCE DETECTED]",
                        "original_line": lines[first_line - 1] if first_line > 0 else line,
                        "detection_method": "statistical",
                    }
                )
            failed_count = 0
            first_line = 0

    if failed_count >= 5:
        findings.append(
            {
                "type": "brute_force",
                "risk": "high",
                "category": "statistical",
                "line": first_line,
                "match": f"Brute force: {failed_count} consecutive failed logins",
                "value": "[ANOMALY: BRUTE FORCE DETECTED]",
                "original_line": lines[first_line - 1] if lines else "",
                "detection_method": "statistical",
            }
        )

    return findings


def classify_ip(ip_str: str) -> Dict[str, str]:
    """
    Classify an IP address with security-focused categories.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback:
            return {
                "category": "loopback",
                "risk": "low",
                "description": "Localhost / loopback address",
            }
        if any(ip in network for network in PRIVATE_NETWORKS):
            return {
                "category": "private",
                "risk": "low",
                "description": "Internal/private network IP",
            }
        if ip.is_reserved:
            return {
                "category": "reserved",
                "risk": "low",
                "description": "Reserved IP range",
            }
        if ip.is_multicast:
            return {
                "category": "multicast",
                "risk": "low",
                "description": "Multicast address",
            }
        return {
            "category": "public",
            "risk": "medium",
            "description": "External / public IP address",
        }
    except ValueError:
        return {
            "category": "invalid",
            "risk": "low",
            "description": "Malformed IP",
        }


def detect_suspicious_ip(lines: List[str]) -> List[Dict]:
    """
    Intelligent IP detection with context-aware risk escalation.
    """
    findings = []
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )

    failed_login_keywords = [
        "failed login",
        "login failed",
        "authentication failed",
        "invalid password",
        "invalid credentials",
        "auth failed",
        "incorrect password",
        "wrong password",
        "access denied",
    ]
    attack_keywords = [
        "sql injection",
        "xss",
        "script",
        "union select",
        "drop table",
        "malicious",
        "exploit",
        "payload",
        "path traversal",
        "../",
        "cmd=",
        "eval(",
    ]
    error_keywords = [
        "error",
        "exception",
        "timeout",
        "refused",
        "blocked",
        "forbidden",
        "unauthorized",
        "unavailable",
    ]

    ip_data = defaultdict(
        lambda: {
            "lines": [],
            "failed_login_lines": [],
            "attack_lines": [],
            "error_lines": [],
            "first_seen": None,
            "raw_lines": [],
        }
    )

    for line_no, line in enumerate(lines, start=1):
        ips = ip_pattern.findall(line)
        line_lower = line.lower()

        for ip in ips:
            entry = ip_data[ip]
            entry["lines"].append(line_no)
            entry["raw_lines"].append(line.strip())

            if entry["first_seen"] is None:
                entry["first_seen"] = line_no

            if any(keyword in line_lower for keyword in failed_login_keywords):
                entry["failed_login_lines"].append(line_no)

            if any(keyword in line_lower for keyword in attack_keywords):
                entry["attack_lines"].append(line_no)

            if any(keyword in line_lower for keyword in error_keywords):
                entry["error_lines"].append(line_no)

    seen_findings = set()

    for ip_str, data in ip_data.items():
        if ip_str in seen_findings:
            continue
        seen_findings.add(ip_str)

        classification = classify_ip(ip_str)
        ip_category = classification["category"]
        appearance_count = len(data["lines"])
        failed_count = len(data["failed_login_lines"])
        attack_count = len(data["attack_lines"])
        error_count = len(data["error_lines"])
        first_line = data["first_seen"] or 1

        if attack_count > 0 and ip_category == "public":
            findings.append(
                {
                    "type": "malicious_ip",
                    "risk": "critical",
                    "category": "network",
                    "match": ip_str,
                    "line": first_line,
                    "value": f"[ATTACKER IP: {ip_str}]",
                    "detail": (
                        f"External IP {ip_str} associated with {attack_count} "
                        f"attack pattern(s) at lines {data['attack_lines'][:3]}"
                    ),
                    "detection_method": "statistical",
                    "context": {
                        "ip_type": ip_category,
                        "appearances": appearance_count,
                        "attack_lines": data["attack_lines"][:5],
                        "failed_logins": failed_count,
                    },
                }
            )
        elif ip_category == "public" and failed_count >= 5:
            findings.append(
                {
                    "type": "attacker_ip",
                    "risk": "critical",
                    "category": "network",
                    "match": ip_str,
                    "line": first_line,
                    "value": f"[ATTACKER IP: {ip_str}]",
                    "detail": (
                        f"External IP {ip_str} has {failed_count} failed "
                        f"login attempts - likely brute force attacker"
                    ),
                    "detection_method": "statistical",
                    "context": {
                        "ip_type": "public",
                        "failed_login_count": failed_count,
                        "failed_login_lines": data["failed_login_lines"][:5],
                        "appearances": appearance_count,
                    },
                }
            )
        elif failed_count >= 3:
            findings.append(
                {
                    "type": "suspicious_ip",
                    "risk": "high",
                    "category": "network",
                    "match": ip_str,
                    "line": first_line,
                    "value": f"[SUSPICIOUS: {ip_str}]",
                    "detail": (
                        f"IP {ip_str} ({ip_category}) has {failed_count} "
                        f"failed login attempts at lines "
                        f"{data['failed_login_lines'][:3]}"
                    ),
                    "detection_method": "statistical",
                    "context": {
                        "ip_type": ip_category,
                        "failed_login_count": failed_count,
                        "appearances": appearance_count,
                    },
                }
            )
        elif ip_category == "public" and appearance_count >= 3:
            findings.append(
                {
                    "type": "repeated_external_ip",
                    "risk": "medium",
                    "category": "network",
                    "match": ip_str,
                    "line": first_line,
                    "value": f"[REPEATED EXTERNAL IP: {ip_str}]",
                    "detail": (
                        f"External IP {ip_str} appears {appearance_count} "
                        f"times in logs - investigate traffic source"
                    ),
                    "detection_method": "statistical",
                    "context": {
                        "ip_type": "public",
                        "appearances": appearance_count,
                        "lines": data["lines"][:5],
                    },
                }
            )
        elif ip_category == "private" and error_count >= 3:
            findings.append(
                {
                    "type": "internal_ip_errors",
                    "risk": "medium",
                    "category": "network",
                    "match": ip_str,
                    "line": first_line,
                    "value": f"[INTERNAL IP ERRORS: {ip_str}]",
                    "detail": (
                        f"Internal IP {ip_str} associated with {error_count} "
                        f"errors - possible misconfiguration or internal threat"
                    ),
                    "detection_method": "statistical",
                    "context": {
                        "ip_type": "private",
                        "error_count": error_count,
                        "appearances": appearance_count,
                    },
                }
            )
        elif ip_category == "private" and appearance_count <= 2:
            continue
        elif ip_category == "public" and appearance_count == 1:
            findings.append(
                {
                    "type": "external_ip",
                    "risk": "low",
                    "category": "network",
                    "match": ip_str,
                    "line": first_line,
                    "value": f"[EXTERNAL IP: {ip_str}]",
                    "detail": f"External IP {ip_str} seen once in logs",
                    "detection_method": "statistical",
                    "context": {
                        "ip_type": "public",
                        "appearances": 1,
                    },
                }
            )

    return findings


def detect_debug_leak(lines: List[str]) -> List[Dict]:
    """Detect debug information leaking through logs."""
    findings = []
    debug_patterns = [
        "debug=true",
        "debug mode",
        "verbose=true",
        "stacktrace",
        "stack_trace",
        "internal server error",
        "at com.",
        "at java.",
        "at org.",
        "at sun.",
    ]
    for line_number, line in enumerate(lines, start=1):
        line_lower = line.lower()
        if any(pattern in line_lower for pattern in debug_patterns):
            findings.append(
                {
                    "type": "debug_leak",
                    "risk": "medium",
                    "category": "leak",
                    "match": line.strip()[:80],
                    "line": line_number,
                    "detail": "Debug information leaked; disable in production",
                    "detection_method": "statistical",
                }
            )

    return findings


def detect_privilege_escalation(lines: List[str]) -> List[Dict]:
    """
    Detect privilege escalation attempts in logs.
    """
    findings = []

    escalation_patterns = [
        (r"sudo.*command not allowed", "Unauthorized sudo command attempt"),
        (r"sudo.*FAILED", "Sudo authentication failure"),
        (r"su\s*:\s*authentication failure", "su privilege escalation failed"),
        (r"www-data.*root", "Web process attempting root access"),
        (r"(?i)unauthorized.*privileged", "Unauthorized privileged access"),
        (r"(?i)failed.*su\b", "Failed su attempt"),
        (r"(?i)(setuid|setgid).*denied", "setuid/setgid denied"),
    ]

    for line_no, line in enumerate(lines, start=1):
        for pattern, description in escalation_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(
                    {
                        "type": "privilege_escalation",
                        "risk": "critical",
                        "category": "system",
                        "match": line.strip()[:80],
                        "line": line_no,
                        "value": "[CRITICAL: PRIVILEGE ESCALATION ATTEMPT]",
                        "detail": description,
                        "detection_method": "statistical",
                    }
                )
                break

    return findings


def analyze_log(text: str) -> Dict:
    """
    Main log analysis function.
    Runs regex detection plus log-specific statistical checks.
    """
    lines = parse_log_lines(text)
    non_empty_lines = [line for line in lines if line.strip()]

    line_findings = [
        finding for finding in detect_all(text) if finding.get("type") != "ip_address"
    ]

    all_findings = []
    all_findings.extend(detect_brute_force(non_empty_lines))
    all_findings.extend(detect_privilege_escalation(non_empty_lines))
    all_findings.extend(detect_suspicious_ip(non_empty_lines))
    all_findings.extend(detect_debug_leak(non_empty_lines))
    all_findings.extend(line_findings)

    statistical_count = sum(
        1 for finding in all_findings if finding.get("detection_method") == "statistical"
    )

    return {
        "findings": all_findings,
        "total_lines": len(non_empty_lines),
        "regex_count": len(line_findings),
        "statistical_count": statistical_count,
    }


def analyze_log_chunked(text: str, chunk_size: int = 1000) -> Dict:
    """
    Process large log files in chunks to avoid memory pressure.
    Merges findings across chunks with corrected line offsets.
    """
    lines = parse_log_lines(text)

    if len(lines) <= chunk_size:
        result = analyze_log(text)
        result["chunked"] = False
        result["chunks_processed"] = 1
        return result

    all_findings = []
    total_lines = len([line for line in lines if line.strip()])

    for chunk_start in range(0, len(lines), chunk_size):
        chunk_lines = lines[chunk_start:chunk_start + chunk_size]
        chunk_text = "\n".join(chunk_lines)

        chunk_result = analyze_log(chunk_text)

        for finding in chunk_result["findings"]:
            adjusted = finding.copy()
            if adjusted.get("line"):
                adjusted["line"] += chunk_start
            all_findings.append(adjusted)

    return {
        "findings": all_findings,
        "total_lines": total_lines,
        "regex_count": sum(
            1 for finding in all_findings
            if finding.get("detection_method") == "regex"
        ),
        "statistical_count": sum(
            1 for finding in all_findings
            if finding.get("detection_method") == "statistical"
        ),
        "chunked": True,
        "chunks_processed": (len(lines) + chunk_size - 1) // chunk_size,
    }
