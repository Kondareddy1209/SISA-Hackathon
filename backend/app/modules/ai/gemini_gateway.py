import os
import json
from typing import Dict, List

import google.generativeai as genai

from app.utils.logger import log_event

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Models to try in order - all work on v1 API without billing
MODELS_TO_TRY = [
    "models/gemini-1.5-flash-8b",
    "models/gemini-1.5-flash",
    "models/gemini-pro",
]


async def analyze_with_gemini(prompt: str, system_prompt: str = "", findings_count: int = 0, content_type: str = "log") -> dict:
    if not GEMINI_API_KEY:
        return {"success": False, "error": True, "type": "NO_API_KEY", "message": "GEMINI_API_KEY not set"}

    full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

    for model_name in MODELS_TO_TRY:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    max_output_tokens=1024,
                )
            )

            if response.text:
                return {
                    "success": True,
                    "content": response.text,
                    "model": model_name,
                    "provider": "google"
                }

        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                continue  # try next model
            elif "404" in error_str or "NOT_FOUND" in error_str:
                continue  # try next model
            else:
                return {
                    "success": False,
                    "error": True,
                    "type": "GEMINI_ERROR",
                    "message": error_str
                }

    return {
        "success": False,
        "error": True,
        "type": "ALL_MODELS_FAILED",
        "message": "All Gemini models failed or quota exceeded"
    }


async def get_gemini_insights(
    findings: List[Dict],
    content_type: str,
    raw_content: str = "",
) -> List[str]:
    """
    Compatibility wrapper for the existing Claude fallback path.
    """
    if not findings:
        log_event("DEBUG", "Gemini insights skipped because no findings were detected", source="gemini_gateway")
        return ["No sensitive data detected. Content appears secure."]

    if not GEMINI_API_KEY:
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
        findings_count=len(findings),
        content_type=content_type,
    )

    result = await analyze_with_gemini(
        prompt,
        findings_count=len(findings),
        content_type=content_type,
    )
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
        model=result.get("model", ""),
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
