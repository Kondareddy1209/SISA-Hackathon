import json
import os
from typing import Dict, List

from google import genai
from google.genai import types

from app.utils.logger import log_event

MODEL_NAME = "gemini-1.5-flash-8b"
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY")) if os.getenv("GEMINI_API_KEY") else None


async def analyze_with_gemini(prompt: str, system_prompt: str = "") -> dict:
    try:
        global client
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            return {
                "success": False,
                "error": True,
                "type": "GEMINI_ERROR",
                "message": "GEMINI_API_KEY not set",
            }

        if client is None:
            client = genai.Client(api_key=api_key)

        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=full_prompt,
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=1024,
            ),
        )

        return {
            "success": True,
            "content": response.text or "",
            "model": MODEL_NAME,
            "provider": "google",
        }

    except Exception as e:
        return {
            "success": False,
            "error": True,
            "type": "GEMINI_ERROR",
            "message": str(e),
        }


async def get_gemini_insights(
    findings: List[Dict],
    content_type: str,
    raw_content: str = "",
) -> List[str]:
    """
    Get AI-powered insights from Google Gemini.
    Falls back gracefully if Gemini is unavailable.
    """
    if not findings:
        log_event("DEBUG", "Gemini insights skipped because no findings were detected", source="gemini_gateway")
        return ["No sensitive data detected. Content appears secure."]

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        log_event("WARN", "Gemini insights skipped because GEMINI_API_KEY is not configured", source="gemini_gateway")
        return []

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

    log_event(
        "INFO",
        "Gemini API call started",
        source="gemini_gateway",
        model=MODEL_NAME,
        findings_count=len(findings),
        content_type=content_type,
    )

    result = await analyze_with_gemini(prompt)
    if not result.get("success"):
        log_event(
            "ERROR",
            f"Gemini API call failed: {result.get('message', 'Unknown error')}",
            source="gemini_gateway",
            error_type=result.get("type", "GEMINI_ERROR"),
        )
        return []

    raw_response = result.get("content", "").strip()
    log_event(
        "INFO",
        "Gemini API call completed",
        source="gemini_gateway",
        model=MODEL_NAME,
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
    except Exception as parse_err:
        log_event("WARN", "Gemini response parsing failed", source="gemini_gateway", error=str(parse_err))
        return []
