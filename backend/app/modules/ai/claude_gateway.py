import asyncio
import json
import os
import traceback
from typing import Dict, List

import anthropic

from app.utils.logger import log_event


def _get_client() -> anthropic.Anthropic:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set")
    return anthropic.Anthropic(api_key=api_key)


def generate_fallback_insights(findings: List[Dict]) -> List[str]:
    """
    Rule-based insights when Claude API is unavailable.
    """
    insights = []
    types = {finding.get("type", "") for finding in findings}

    type_map = {
        "password": ("CRITICAL", "Password exposed in plain text - change immediately and audit all access logs"),
        "api_key": ("HIGH", "API key exposed - rotate via provider dashboard immediately"),
        "aws_key": ("CRITICAL", "AWS access key exposed - disable in IAM console immediately and review CloudTrail"),
        "secret": ("CRITICAL", "Hardcoded secret detected - move to environment variables and revoke the exposed value"),
        "hardcoded_secret": ("CRITICAL", "Hardcoded auth secret - rotate and store it in a secrets manager"),
        "private_key_block": ("CRITICAL", "Private key material exposed - revoke the keypair and reissue credentials immediately"),
        "connection_string": ("CRITICAL", "Database connection string exposed - rotate credentials and restrict network access"),
        "bearer_token": ("HIGH", "Bearer token exposed - revoke and reissue this token immediately"),
        "jwt_token": ("HIGH", "JWT token exposed - invalidate the token and audit active sessions"),
        "token": ("HIGH", "Auth token exposed - revoke and reissue"),
        "brute_force": ("HIGH", "Brute force attack detected - block the source IP and enable rate limiting"),
        "privilege_escalation": ("CRITICAL", "Privilege escalation attempt detected - isolate the host and review sudo or su activity"),
        "sql_injection": ("HIGH", "SQL injection patterns found - switch to parameterized queries immediately"),
        "xss_attempt": ("HIGH", "XSS payloads detected - sanitize output and enforce contextual encoding"),
        "path_traversal": ("HIGH", "Path traversal patterns detected - validate and normalize all file paths"),
        "command_injection": ("HIGH", "Command injection patterns detected - sanitize inputs before execution"),
        "stack_trace": ("MEDIUM", "Stack trace reveals internals - disable verbose errors in production"),
        "debug_mode": ("MEDIUM", "Debug mode appears active - disable it to reduce information disclosure"),
        "ssn": ("CRITICAL", "Social Security Number detected - remove from logs and apply stronger PII redaction"),
        "credit_card": ("CRITICAL", "Credit card data detected - redact immediately and verify PCI scope"),
        "email": ("LOW", "Email addresses appear in content - review retention policy and sanitize logs"),
        "high_entropy_string": ("HIGH", "High-entropy string detected - likely an exposed secret or token"),
        "failure_rate_spike": ("HIGH", "Failure rate spike detected - investigate authentication or access control abuse"),
        "multi_pattern_line": ("CRITICAL", "Multiple sensitive patterns occur on the same line - treat this as a high-confidence threat indicator"),
        "malicious_ip": ("CRITICAL", "Malicious external IP correlated with attack behavior - block and investigate immediately"),
    }

    for finding_type, (level, message) in type_map.items():
        if finding_type in types:
            matching = next(
                (finding for finding in findings if finding.get("type") == finding_type),
                None,
            )
            line_ref = (
                f" (line {matching['line']})"
                if matching and matching.get("line")
                else ""
            )
            insights.append(f"{level}: {message}{line_ref}")
            if len(insights) >= 4:
                break

    if not insights:
        insights.append(
            "Review all detected findings, rotate exposed credentials, and apply least privilege."
        )

    return insights


async def get_ai_insights(
    findings: List[Dict],
    content_type: str,
    raw_content: str = "",
) -> List[str]:
    """
    Get AI-powered insights from Claude.
    Falls back to rule-based insights if Claude is unavailable or parsing fails.
    """
    if not findings:
        log_event("DEBUG", "AI insights skipped because no findings were detected", source="ai_gateway")
        return ["No sensitive data detected. Content appears secure."]

    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        log_event("WARN", "AI insights fallback because ANTHROPIC_API_KEY is not configured", source="ai_gateway")
        return generate_fallback_insights(findings)

    raw_response = ""
    try:
        client = _get_client()
        log_event(
            "INFO",
            "AI model call started",
            source="ai_gateway",
            model="claude-sonnet-4-6",
            findings_count=len(findings),
            content_type=content_type,
        )

        findings_summary = json.dumps(
            [
                {
                    "type": finding.get("type"),
                    "risk": finding.get("risk"),
                    "line": finding.get("line"),
                    "category": finding.get("category"),
                    "detail": finding.get("detail", ""),
                }
                for finding in findings[:12]
            ],
            indent=2,
        )

        prompt = f"""You are a cybersecurity analyst reviewing {content_type} content.

The following security findings were detected by automated scanners:
{findings_summary}

Content statistics:
- Total findings: {len(findings)}
- Critical findings: {sum(1 for f in findings if f.get('risk') == 'critical')}
- Detection methods used: Regex, Statistical (Z-score), ML (Isolation Forest)

Provide a security analysis with EXACTLY this JSON structure:
{{
  "insights": [
    "Specific actionable insight 1 referencing actual finding types",
    "Specific actionable insight 2 with line numbers if available",
    "Specific actionable insight 3 with immediate remediation step"
  ],
  "attack_classification": "brute_force|credential_exposure|injection|data_leak|unknown",
  "immediate_actions": ["action1", "action2"]
}}

Rules:
- Reference actual finding types (password, api_key, brute_force, etc.)
- Include line numbers when available
- Be specific, not generic
- Return ONLY the JSON, no markdown, no extra text"""

        loop = asyncio.get_event_loop()
        try:
            message = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: client.messages.create(
                        model="claude-sonnet-4-6",
                        max_tokens=600,
                        messages=[{"role": "user", "content": prompt}],
                    ),
                ),
                timeout=25.0,
            )
        except anthropic.BadRequestError as e:
            if "credit balance is too low" in str(e).lower():
                log_event(
                    "ERROR",
                    "Anthropic API credits exhausted",
                    source="ai_gateway",
                    error_type="INSUFFICIENT_CREDITS"
                )
                return {
                    "error": True,
                    "type": "INSUFFICIENT_CREDITS",
                    "message": "AI service temporarily unavailable. API credits exhausted.",
                    "fallback": "Please contact administrator to top up API credits."
                }
            raise e

        raw_response = message.content[0].text.strip()
        log_event(
            "INFO",
            "AI model call completed",
            source="ai_gateway",
            model="claude-sonnet-4-6",
            response_preview=raw_response[:120],
        )

        clean_response = raw_response
        for fence in ("```json", "```JSON", "```"):
            clean_response = clean_response.replace(fence, "")
        clean_response = clean_response.strip()

        try:
            parsed = json.loads(clean_response)
            insights = parsed.get("insights", [])

            attack_type = parsed.get("attack_classification", "")
            if attack_type and attack_type != "unknown":
                insights.insert(
                    0,
                    f"Attack Classification: {attack_type.upper().replace('_', ' ')}",
                )

            actions = parsed.get("immediate_actions", [])
            for action in actions[:2]:
                insights.append(f"Action Required: {action}")

            return [str(insight) for insight in insights[:6]]
        except Exception:
            log_event("WARN", "AI response parsing failed, using fallback insights", source="ai_gateway")
            return generate_fallback_insights(findings)

    except asyncio.TimeoutError:
        log_event("ERROR", "AI model call timed out after 25s", source="ai_gateway")
        return {
            "error": True,
            "type": "AI_TIMEOUT",
            "message": "AI analysis timed out",
            "fallback": "Using rule-based analysis"
        }
    except anthropic.AuthenticationError as e:
        log_event(
            "ERROR", 
            "AI authentication failed - check ANTHROPIC_API_KEY validity", 
            source="ai_gateway",
            error_detail=str(e)
        )
        return {
            "error": True,
            "type": "AUTH_ERROR",
            "message": "AI authentication failed",
            "fallback": "Using rule-based analysis"
        }
    except anthropic.RateLimitError:
        log_event("WARN", "AI rate limit exceeded", source="ai_gateway")
        return {
            "error": True,
            "type": "RATE_LIMIT",
            "message": "AI rate limit exceeded",
            "fallback": "Using rule-based analysis"
        }
    except anthropic.APIConnectionError as e:
        log_event(
            "ERROR", 
            "Could not connect to AI service", 
            source="ai_gateway",
            error_detail=str(e)
        )
        return {
            "error": True,
            "type": "CONNECTION_ERROR",
            "message": "Could not connect to AI service",
            "fallback": "Using rule-based analysis"
        }
    except Exception as exc:
        log_event(
            "ERROR",
            f"AI model call failed with {type(exc).__name__}",
            source="ai_gateway",
            error=str(exc),
        )
        return {
            "error": True,
            "type": "AI_ERROR",
            "message": str(exc),
            "fallback": "Using rule-based analysis"
        }

    return generate_fallback_insights(findings)
