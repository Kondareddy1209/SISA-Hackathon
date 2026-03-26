import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_analyze_log():
    import pytest
    from fastapi.testclient import TestClient
    from app.main import app


    client = TestClient(app)


    def test_health():
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "version" in data


    def test_analyze_log():
        payload = {
            "input_type": "log",
            "content": "password=EXAMPLEPASS\napi_key=sk-EXAMPLE000000000\nemail=test@example.com",
            "options": {"mask_output": True, "use_ai": False, "block_on_critical": True},
        }
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert "findings" in data
        assert "risk_level" in data
        assert "risk_score" in data
        assert "action" in data
        assert isinstance(data["findings"], list)


    def test_analyze_text():
        payload = {
            "input_type": "text",
            "content": "Contact me at john@example.com or call +1-555-123-4567",
            "options": {"mask_output": True, "use_ai": False, "block_on_critical": False},
        }
        r = client.post("/api/analyze", json=payload)
        assert r.status_code == 200
    assert "version" in data


def test_analyze_log():
    payload = {
        "input_type": "log",
        "content": "password=EXAMPLEPASS\napi_key=sk-EXAMPLE000000000\nemail=test@example.com",
        "options": {"mask_output": True, "use_ai": False, "block_on_critical": True},
    }
    r = client.post("/api/analyze", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "findings" in data
    assert "risk_level" in data
    assert "risk_score" in data
    assert "action" in data
    assert isinstance(data["findings"], list)


def test_analyze_text():
    payload = {
        "input_type": "text",
        "content": "Contact me at john@example.com or call +1-555-123-4567",
        "options": {"mask_output": True, "use_ai": False, "block_on_critical": False},
    }
    r = client.post("/api/analyze", json=payload)
    assert r.status_code == 200
