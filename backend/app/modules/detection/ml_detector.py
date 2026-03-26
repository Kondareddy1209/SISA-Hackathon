import math
from collections import Counter
from typing import Dict, List


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in freq.values()
    )


def extract_features(text: str) -> Dict[str, float]:
    """
    Extract numerical features from text for ML-style anomaly scoring.
    """
    lines = [line for line in text.split("\n") if line.strip()]
    total_chars = len(text)

    credential_kws = ["password", "secret", "token", "api_key", "bearer", "auth"]
    error_kws = ["error", "failed", "exception", "denied", "unauthorized"]
    injection_kws = ["select", "union", "drop", "script", "eval", "exec"]

    return {
        "line_count": len(lines),
        "avg_line_length": (
            sum(len(line) for line in lines) / len(lines) if lines else 0
        ),
        "entropy": calculate_entropy(text),
        "credential_keyword_density": sum(
            text.lower().count(keyword) for keyword in credential_kws
        ) / max(total_chars, 1) * 1000,
        "error_keyword_density": sum(
            text.lower().count(keyword) for keyword in error_kws
        ) / max(total_chars, 1) * 1000,
        "injection_keyword_density": sum(
            text.lower().count(keyword) for keyword in injection_kws
        ) / max(total_chars, 1) * 1000,
        "special_char_ratio": sum(
            1 for char in text if not char.isalnum() and not char.isspace()
        ) / max(total_chars, 1),
        "uppercase_ratio": sum(
            1 for char in text if char.isupper()
        ) / max(total_chars, 1),
        "digit_ratio": sum(
            1 for char in text if char.isdigit()
        ) / max(total_chars, 1),
    }


def isolation_forest_score(features: Dict[str, float]) -> float:
    """
    Lightweight anomaly score inspired by Isolation Forest.
    """
    score = 0.0
    weights = {
        "entropy": (0.0, 3.5, 4.5, 0.25),
        "credential_keyword_density": (0.0, 1.0, 3.0, 0.30),
        "error_keyword_density": (0.0, 2.0, 5.0, 0.15),
        "injection_keyword_density": (0.0, 0.5, 2.0, 0.20),
        "special_char_ratio": (0.0, 0.15, 0.35, 0.10),
    }

    for feature, (_, mid_val, max_val, weight) in weights.items():
        value = features.get(feature, 0)
        if value > mid_val:
            normalized = min(
                (value - mid_val) / max(max_val - mid_val, 0.001),
                1.0,
            )
            score += normalized * weight

    return round(min(score, 1.0), 3)


def detect_ml_anomalies(text: str, existing_findings: List[Dict]) -> List[Dict]:
    """
    ML-layer detection using Isolation Forest-inspired scoring.
    """
    findings = []
    features = extract_features(text)
    anomaly_score = isolation_forest_score(features)

    existing_count = len(existing_findings)
    critical_count = sum(
        1 for finding in existing_findings if finding.get("risk") == "critical"
    )
    boosted_score = min(
        anomaly_score + (critical_count * 0.05) + (existing_count * 0.01),
        1.0,
    )

    if (
        (
            features["credential_keyword_density"] > 0.5
            or features["line_count"] <= 2
        )
        and features["entropy"] > 4.2
    ):
        credential_risk = "high" if features["line_count"] <= 2 else "low"
        findings.append(
            {
                "type": "credential_density_anomaly",
                "risk": credential_risk,
                "category": "ml",
                "line": 1,
                "match": f"Score={boosted_score:.3f}",
                "value": "[ML: CREDENTIAL DENSITY ANOMALY]",
                "detail": (
                    f"ML anomaly score={boosted_score:.3f} - "
                    "High credential keyword density with elevated entropy"
                ),
                "detection_method": "ml",
                "ml_features": {
                    "anomaly_score": boosted_score,
                    "entropy": features["entropy"],
                    "credential_density": features["credential_keyword_density"],
                },
            }
        )

    if features["injection_keyword_density"] > 1.0:
        findings.append(
            {
                "type": "injection_pattern_anomaly",
                "risk": "high",
                "category": "ml",
                "line": 1,
                "match": f"Score={boosted_score:.3f}",
                "value": "[ML: INJECTION ANOMALY]",
                "detail": (
                    "ML detected injection patterns - "
                    f"density={features['injection_keyword_density']:.3f}"
                ),
                "detection_method": "ml",
                "ml_features": {
                    "anomaly_score": boosted_score,
                    "injection_density": features["injection_keyword_density"],
                },
            }
        )

    if boosted_score > 0.85 and existing_count >= 4:
        findings.append(
            {
                "type": "multi_pattern_correlation",
                "risk": "critical",
                "category": "ml",
                "line": 1,
                "match": f"Score={boosted_score:.3f}",
                "value": "[ML: HIGH RISK CORRELATION]",
                "detail": (
                    f"ML correlation: {existing_count} findings with "
                    f"anomaly_score={boosted_score:.3f} - "
                    "Multiple attack vectors detected simultaneously"
                ),
                "detection_method": "ml",
                "ml_features": {
                    "anomaly_score": boosted_score,
                    "correlated_findings": existing_count,
                    "critical_findings": critical_count,
                },
            }
        )

    return findings
