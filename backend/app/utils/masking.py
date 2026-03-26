from typing import Dict


def mask_api_key(value: str) -> str:
    """Mask API keys keeping a recognizable prefix for `sk-` style keys.

    Example: "sk-EXAMPLE000000000" -> "sk-***REDACTED***"
    """
    if not value:
        return value
    if value.startswith("sk-"):
        return "sk-***REDACTED***"
    return "***REDACTED***"


def mask_password(value: str) -> str:
    """Return a fixed redaction string for password values."""
    if not value:
        return value
    return "[PASSWORD REDACTED]"


def mask_email(value: str) -> str:
    """Mask an email address preserving the top-level domain.

    Example: "user@example.com" -> "u***@***.com"
    """
    if not value or "@" not in value:
        return value
    try:
        local, domain = value.split("@", 1)
        tld = domain.split('.')[-1] if '.' in domain else 'com'
        first = local[0] if local else 'u'
        return f"{first}***@***.{tld}"
    except ValueError:
        return "***@***.com"


def mask_token(value: str) -> str:
    """Mask bearer/jwt/token values with a fixed marker."""
    if not value:
        return value
    return "[TOKEN REDACTED]"


def mask_finding(text: str, finding_type: str, match: str) -> str:
    """Given the original text, a finding type and the matched substring, return the text
    with the first occurrence of the match replaced by an appropriate masked value.
    """
    if not text or not match:
        return text
    masked = None
    if finding_type == "api_key":
        masked = mask_api_key(match)
    elif finding_type == "password":
        masked = mask_password(match)
    elif finding_type == "email":
        masked = mask_email(match)
    elif finding_type == "token":
        masked = mask_token(match)
    else:
        masked = "[REDACTED]"
    return text.replace(match, masked, 1)

