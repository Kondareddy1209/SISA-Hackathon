import asyncio
from app.modules.parser.log_parser import parse_log
from app.modules.detection.log_analyzer import analyze_log


SAMPLE_LOG = """2026-03-10 10:00:01 INFO User login
email=admin@company.com
password=TEST_ONLY
api_key=sk-EXAMPLE000000000
ERROR stack trace: NullPointerException at service.java:45"""


def test_log_findings():
    lines = parse_log(SAMPLE_LOG)
    options = {"use_ai": False, "mask_output": True, "block_on_critical": True}
    result = asyncio.get_event_loop().run_until_complete(analyze_log(lines, options))
    types = [f["type"] for f in result["findings"]]
    assert "email" in types
    assert "password" in types
    assert "api_key" in types
    risks = {f["type"]: f["risk"] for f in result["findings"]}
    assert risks.get("email") == "low"
    assert risks.get("password") == "critical"
    assert risks.get("api_key") == "high"
    assert result["risk_level"] in ("high", "critical")
