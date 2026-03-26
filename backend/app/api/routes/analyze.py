import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ValidationError

from app.modules.ai.claude_gateway import get_ai_insights
from app.modules.detection.log_analyzer import analyze_log_chunked
from app.modules.detection.ml_detector import detect_ml_anomalies
from app.modules.detection.regex_engine import detect_all, get_all_patterns
from app.modules.detection.statistical_detector import detect_statistical_anomalies
from app.modules.policy.policy_engine import apply_masking, determine_action
from app.modules.risk.risk_engine import (
    calculate_risk_score,
    get_risk_level,
    get_risk_summary,
)
from app.utils.logger import log_event

router = APIRouter()
security = HTTPBearer(auto_error=False)
MAX_CONTENT_CHARS = 500_000


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Bearer token auth is opt-in for deployed public frontends."""
    auth_enabled = os.getenv("REQUIRE_API_BEARER_TOKEN", "").lower() == "true"
    if not auth_enabled:
        log_event("DEBUG", "Auth bypassed for request", auth="disabled")
        return

    configured = os.getenv("API_BEARER_TOKEN", "")
    if configured and configured != "changeme":
        if not credentials or credentials.credentials != configured:
            log_event("WARN", "Bearer token rejected", auth="failed")
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing bearer token",
            )
        log_event("INFO", "Bearer token accepted", auth="success")


class AnalyzeOptions(BaseModel):
    mask: bool = True
    block_high_risk: bool = True
    log_analysis: bool = True
    use_ai: bool = True


class AnalyzeRequest(BaseModel):
    input_type: str = Field(
        ...,
        pattern="^(text|file|sql|chat|log)$",
        description="One of: text, file, sql, chat, log",
    )
    content: str = Field(..., min_length=1)
    options: AnalyzeOptions = AnalyzeOptions()


def _model_to_dict(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _infer_input_type(filename: str, fallback: str = "file") -> str:
    lowered = (filename or "").lower()
    if lowered.endswith(".log"):
        return "log"
    if lowered.endswith(".sql"):
        return "sql"
    return fallback


def _dedupe_findings(findings: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    deduped = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("type"),
            finding.get("line"),
            finding.get("match"),
            finding.get("detail"),
            finding.get("detection_method"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


@router.post("/analyze")
async def analyze(
    request: Request,
    _token=Depends(verify_token),
):
    """
    Main analysis endpoint.
    Runs: Regex -> Statistical -> ML -> AI -> Risk -> Policy
    Matches official project spec API contract exactly.
    """
    content_type = request.headers.get("content-type", "")
    log_event("INFO", "Analysis request received", route="/analyze", content_type=content_type or "unknown")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        options_raw = form.get("options", "{}")

        if uploaded_file and hasattr(uploaded_file, "read"):
            content = (await uploaded_file.read()).decode("utf-8", errors="ignore")
            input_type = _infer_input_type(
                getattr(uploaded_file, "filename", ""),
                str(form.get("input_type", "file")),
            )
        else:
            content = str(form.get("content", ""))
            input_type = str(form.get("input_type", "text"))

        try:
            options_payload = (
                json.loads(options_raw)
                if isinstance(options_raw, str)
                else options_raw
            )
        except json.JSONDecodeError:
            options_payload = {
                "mask": True,
                "block_high_risk": True,
                "log_analysis": True,
                "use_ai": True,
            }

        payload: Dict[str, Any] = {
            "input_type": input_type,
            "content": content,
            "options": options_payload or {},
        }
    else:
        body_bytes = await request.body()
        try:
            payload = json.loads(body_bytes)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc

    try:
        validated = AnalyzeRequest(**payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    content = validated.content.strip()
    if not content:
        raise HTTPException(status_code=422, detail="Content must not be empty.")

    if len(content) > MAX_CONTENT_CHARS:
        content = content[:MAX_CONTENT_CHARS]
        truncated = True
    else:
        truncated = False

    input_type = validated.input_type
    options = _model_to_dict(validated.options)

    if input_type == "log" and options.get("log_analysis", True):
        log_result = analyze_log_chunked(content)
        regex_findings = [
            finding
            for finding in log_result["findings"]
            if finding.get("detection_method") == "regex"
        ]
        log_statistical_findings = [
            finding
            for finding in log_result["findings"]
            if finding.get("detection_method") == "statistical"
        ]
        statistical_findings = _dedupe_findings(
            log_statistical_findings + detect_statistical_anomalies(content, input_type)
        )
        total_lines = log_result["total_lines"]
    else:
        regex_findings = detect_all(content)
        statistical_findings = _dedupe_findings(
            detect_statistical_anomalies(content, input_type)
        )
        total_lines = len([line for line in content.split("\n") if line.strip()])

    regex_findings = _dedupe_findings(regex_findings)
    all_so_far = _dedupe_findings(regex_findings + statistical_findings)
    ml_findings = _dedupe_findings(detect_ml_anomalies(content, all_so_far))
    all_findings = _dedupe_findings(all_so_far + ml_findings)

    risk_score = calculate_risk_score(all_findings)
    risk_level = get_risk_level(risk_score)
    summary = get_risk_summary(all_findings, input_type)

    ai_insights = []
    ai_findings_count = 0
    if options.get("use_ai", True) and all_findings:
        ai_insights = await get_ai_insights(
            findings=all_findings,
            content_type=input_type,
            raw_content=content[:2000],
        )
        
        # Check if AI returned an error
        if isinstance(ai_insights, dict) and ai_insights.get("error") is True:
            error_type = ai_insights.get("type", "UNKNOWN")
            
            if error_type == "INSUFFICIENT_CREDITS":
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "AI_SERVICE_UNAVAILABLE",
                        "message": "AI service temporarily unavailable. API credits exhausted.",
                        "action": "Please contact administrator to top up API credits.",
                        "service": "Anthropic Claude"
                    }
                )
            elif error_type in ["AUTH_ERROR", "CONNECTION_ERROR", "RATE_LIMIT"]:
                # These are transient AI service issues - fall back gracefully
                log_event(
                    "WARN", 
                    f"AI service unavailable ({error_type}), using rule-based analysis", 
                    route="/analyze",
                    error_type=error_type
                )
                ai_insights = []
            else:
                # Other AI errors - also fall back
                log_event("WARN", f"AI error encountered: {error_type}", route="/analyze", error_type=error_type)
                ai_insights = []
        else:
            is_fallback = not ai_insights or (isinstance(ai_insights, list) and len(ai_insights) > 0 and any(
                phrase in ai_insights[0].lower()
                for phrase in ["unavailable", "appears secure", "review all"]
            ))
            ai_findings_count = len(ai_insights) if not is_fallback else 0
    elif not all_findings:
        ai_insights = ["No sensitive data detected. Content appears secure."]

    action = determine_action(risk_level, options)
    masked_findings = apply_masking(all_findings, options.get("mask", True))

    return {
        "summary": summary,
        "content_type": input_type,
        "total_lines_analyzed": total_lines,
        "findings": masked_findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action,
        "insights": ai_insights,
        "detection_breakdown": {
            "regex": len(regex_findings),
            "statistical": len(statistical_findings),
            "ml": len(ml_findings),
            "ai": ai_findings_count,
        },
        "truncated": truncated,
        "note": "Content truncated to 500KB limit" if truncated else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health")
async def health():
    import time
    return {
        "status": "ok",
        "version": os.getenv("APP_VERSION", "1.0.0"),
        "model": "claude-sonnet-4-6",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/patterns")
async def patterns():
    """Return all detection patterns and their risk levels."""
    return {
        "patterns": get_all_patterns(),
        "total": len(get_all_patterns()),
    }
