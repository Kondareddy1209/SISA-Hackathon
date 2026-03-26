import re
from typing import List, Dict, Tuple

MASK_RULES = {
    "email": lambda v: re.sub(
        r'(\w{1,2})\w*@(\w{1,2})\w*\.',
        lambda m: m.group(1) + '***@' + m.group(2) + '***.',
        v
    ),
    "password": lambda v: re.sub(
        r'(?i)(password|passwd|pwd|pass)\s*(?:is\s+|=\s*|:\s*)\S+',
        lambda m: m.group().split(m.group(1))[-1].split()[-1] and 
                  m.group(1) + '=[REDACTED]',
        v
    ),
    "api_key": lambda v: re.sub(
        r'(sk-[A-Za-z0-9]{4})[A-Za-z0-9]+([A-Za-z0-9]{4})',
        r'\1***\2', v
    ),
    "bearer_token": lambda v: re.sub(
        r'(Bearer\s+[A-Za-z0-9]{4})[A-Za-z0-9\-._~+/]+=*',
        r'\1[TOKEN REDACTED]', v, flags=re.IGNORECASE
    ),
    "jwt_token": lambda v: re.sub(
        r'(eyJ[A-Za-z0-9\-_]{4})[A-Za-z0-9\-_.]+',
        r'\1[JWT REDACTED]', v
    ),
}

SIMPLE_MASK = "[MASKED]"
def mask_finding_value(value: str, finding_type: str) -> str:
    """Apply type-specific masking to a sensitive value"""
    masker = MASK_RULES.get(finding_type)
    if masker:
        try:
            return masker(value)
        except Exception:
            pass
    return SIMPLE_MASK


def determine_action(risk_level: str, options: Dict) -> str:
    """
    Determine policy action based on risk level and options.
    Returns: 'blocked' | 'masked' | 'allowed'
    """
    block_high_risk = options.get("block_high_risk", True)
    mask = options.get("mask", True)

    if block_high_risk and risk_level == "critical":
        return "blocked"
    elif mask:
        return "masked"
    return "allowed"


def apply_masking(findings: List[Dict], mask: bool) -> List[Dict]:
    """
    Apply masking to all findings values.
    Returns findings with 'value' field populated.
    """
    result = []
    for f in findings:
        finding = f.copy()
        raw_value = f.get("match", "")
        if mask:
            finding["value"] = mask_finding_value(
                raw_value, f.get("type", "")
            )
        else:
            finding["value"] = raw_value
        # Remove raw match from response for security
        finding.pop("match", None)
        finding.pop("start", None)
        finding.pop("end", None)
        result.append(finding)
    return result
