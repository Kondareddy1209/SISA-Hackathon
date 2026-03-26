import math
import re
from collections import Counter
from typing import Dict, List


def calculate_entropy(text: str) -> float:
    """
    Shannon entropy - high entropy suggests secrets or random tokens.
    """
    if not text or len(text) < 8:
        return 0.0
    freq = Counter(text)
    total = len(text)
    entropy = -sum(
        (count / total) * math.log2(count / total)
        for count in freq.values()
    )
    return round(entropy, 3)


def detect_high_entropy_strings(text: str) -> List[Dict]:
    """
    Detect high-entropy strings likely to be credentials or tokens.
    """
    findings = []
    pattern = re.compile(r"[a-zA-Z0-9+/=_\-]{20,}")
    seen_values = set()

    lines = text.split("\n")
    for line_num, line in enumerate(lines, start=1):
        for match in pattern.finditer(line):
            value = match.group()
            if value in seen_values:
                continue
            seen_values.add(value)
            entropy = calculate_entropy(value)

            if entropy > 4.5:
                findings.append(
                    {
                        "type": "high_entropy_string",
                        "risk": "high",
                        "category": "statistical",
                        "match": value[:40] + "..." if len(value) > 40 else value,
                        "line": line_num,
                        "value": "[HIGH ENTROPY - POSSIBLE SECRET]",
                        "detail": (
                            f"Shannon entropy={entropy} (>4.5 threshold) - "
                            "likely credential or token"
                        ),
                        "detection_method": "statistical",
                    }
                )

    return findings


def detect_credential_density(text: str, input_type: str) -> List[Dict]:
    """
    Detect lines with abnormally high density of credential language.
    """
    findings = []
    credential_keywords = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "auth",
        "credential",
        "private",
        "key",
        "bearer",
    ]

    lines = text.split("\n")
    keyword_counts = []

    for line in lines:
        line_lower = line.lower()
        count = sum(1 for keyword in credential_keywords if keyword in line_lower)
        keyword_counts.append(count)

    if not keyword_counts:
        return findings

    mean = sum(keyword_counts) / len(keyword_counts)
    variance = sum((value - mean) ** 2 for value in keyword_counts) / len(keyword_counts)
    std_dev = math.sqrt(variance) if variance > 0 else 0

    for index, (line, count) in enumerate(zip(lines, keyword_counts), start=1):
        z_score = (count - mean) / std_dev if std_dev > 0 else 0

        if z_score > 2.0 and count >= 2:
            findings.append(
                {
                    "type": "credential_density_anomaly",
                    "risk": "high",
                    "category": "statistical",
                    "match": line.strip()[:80],
                    "line": index,
                    "value": "[CREDENTIAL DENSITY ANOMALY]",
                    "detail": (
                        f"Line has {count} credential keywords "
                        f"(z-score={z_score:.2f}, threshold=2.0)"
                    ),
                    "detection_method": "statistical",
                }
            )

    return findings


def detect_multi_pattern_line(text: str) -> List[Dict]:
    """
    Flag lines containing multiple different sensitive pattern classes.
    """
    findings = []

    pattern_checks = {
        "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "credential_keyword": re.compile(
            r"(?i)(password|api_key|secret|token|bearer)\s*[=:]\s*\S+"
        ),
        "number_sequence": re.compile(r"\b\d{4,}\b"),
        "path": re.compile(r"(/[a-zA-Z0-9_\-]+){3,}"),
    }

    for index, line in enumerate(text.split("\n"), start=1):
        matched_types = [
            name for name, pattern in pattern_checks.items() if pattern.search(line)
        ]

        if len(matched_types) >= 3:
            findings.append(
                {
                    "type": "multi_pattern_line",
                    "risk": "high",
                    "category": "statistical",
                    "match": line.strip()[:80],
                    "line": index,
                    "value": "[MULTI-PATTERN ANOMALY]",
                    "detail": (
                        f"Line matches {len(matched_types)} pattern types: "
                        f"{', '.join(matched_types)}"
                    ),
                    "detection_method": "statistical",
                }
            )

    return findings


def detect_repeated_failures(text: str) -> List[Dict]:
    """
    Detect sudden spikes of failure-related events using a z-score window.
    """
    findings = []
    failure_keywords = [
        "failed",
        "error",
        "denied",
        "rejected",
        "unauthorized",
        "forbidden",
        "invalid",
    ]

    lines = text.split("\n")
    window_size = 10
    failure_counts = []

    for start in range(0, len(lines), window_size):
        window = lines[start:start + window_size]
        count = sum(
            1 for line in window
            if any(keyword in line.lower() for keyword in failure_keywords)
        )
        failure_counts.append((start, count))

    if len(failure_counts) < 2:
        return findings

    counts = [count for _, count in failure_counts]
    mean = sum(counts) / len(counts)
    variance = sum((value - mean) ** 2 for value in counts) / len(counts)
    std_dev = math.sqrt(variance) if variance > 0 else 0

    for start_line, count in failure_counts:
        z_score = (count - mean) / std_dev if std_dev > 0 else 0

        if z_score > 2.5 and count >= 5:
            findings.append(
                {
                    "type": "failure_rate_spike",
                    "risk": "high",
                    "category": "statistical",
                    "match": (
                        f"{count} failures in lines "
                        f"{start_line + 1}-{start_line + window_size}"
                    ),
                    "line": start_line + 1,
                    "value": "[ANOMALY: FAILURE RATE SPIKE]",
                    "detail": (
                        f"Failure rate z-score={z_score:.2f} "
                        f"({count} failures in {window_size}-line window)"
                    ),
                    "detection_method": "statistical",
                }
            )

    return findings


def detect_statistical_anomalies(text: str, input_type: str) -> List[Dict]:
    """
    Main statistical detection function.
    """
    findings = []
    findings.extend(detect_high_entropy_strings(text))
    findings.extend(detect_credential_density(text, input_type))
    findings.extend(detect_multi_pattern_line(text))

    # Direct injection density check (works on single-line SQL too)
    injection_keywords = [
        "select", "union", "drop", "insert", "delete",
        "exec", "alter", "truncate", "execute",
    ]
    text_lower = text.lower()
    injection_hits = sum(
        text_lower.count(keyword) for keyword in injection_keywords
    )
    total_words = max(len(text.split()), 1)
    injection_ratio = injection_hits / total_words

    if injection_hits >= 3:
        findings.append(
            {
                "type": "injection_keyword_density",
                "risk": "high",
                "category": "statistical",
                "match": f"{injection_hits} injection keywords detected",
                "line": None,
                "value": "[STATISTICAL: HIGH INJECTION DENSITY]",
                "detail": (
                    f"Statistical: {injection_hits} SQL/injection keywords "
                    f"(ratio={injection_ratio:.3f}) - likely malicious query"
                ),
                "detection_method": "statistical",
            }
        )

    credential_keywords_direct = [
        "password", "secret", "token", "api_key",
        "bearer", "auth", "credential", "private_key",
    ]
    cred_hits = sum(
        text_lower.count(keyword) for keyword in credential_keywords_direct
    )
    if cred_hits >= 2:
        findings.append(
            {
                "type": "credential_keyword_density",
                "risk": "high",
                "category": "statistical",
                "match": f"{cred_hits} credential keywords in content",
                "line": None,
                "value": "[STATISTICAL: CREDENTIAL DENSITY]",
                "detail": (
                    f"Statistical: {cred_hits} credential-related keywords "
                    "detected - likely sensitive content"
                ),
                "detection_method": "statistical",
            }
        )

    if input_type in ("log", "file", "sql", "text", "chat"):
        findings.extend(detect_repeated_failures(text))

    return findings
