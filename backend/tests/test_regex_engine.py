from app.modules.detection.regex_engine import detect_all


def test_detect_api_key_and_password_and_email_and_token():
    r1 = detect_all("sk-EXAMPLE000000000")
    assert any(f["type"] == "api_key" and f["risk"] == "high" for f in r1)

    r2 = detect_all("password=EXAMPLEPASS")
    assert any(f["type"] == "password" and f["risk"] == "critical" for f in r2)

    r3 = detect_all("test@example.com")
    assert any(f["type"] == "email" and f["risk"] == "low" for f in r3)

    r4 = detect_all("bearer eyJhbGciOiJIUzI1NiJ9")
    assert any(f["type"] == "token" and f["risk"] == "high" for f in r4)
from app.modules.detection.regex_engine import detect_all



