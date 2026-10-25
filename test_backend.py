import pytest
import io
from PIL import Image
from fastapi.testclient import TestClient
from main import app
from database import init_db, clear_all_scans

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "Digital Trust" in res.json().get("service", "Digital Trust API") or "engine" in data

def test_analyze_message_high_risk():
    payload = {
        "text": "URGENT: Your Wells Fargo bank account is suspended! Send your OTP code 948271 immediately or legal action will be taken within 24 hours. Click here: http://wells-verify.com"
    }
    res = client.post("/api/analyze-message", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_category"] == "High Risk"
    assert data["risk_score"] >= 65
    assert len(data["indicators"]) >= 2
    assert len(data["recommendations"]) >= 1
    # Check that plain OTP wasn't stored raw in target_summary
    assert "948271" not in data["target_summary"]

def test_analyze_message_low_risk():
    payload = {
        "text": "Hi Sarah, can you please send me the presentation slides when you have a moment? Thanks!"
    }
    res = client.post("/api/analyze-message", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_category"] == "Low Risk"
    assert data["risk_score"] < 30

def test_analyze_url_high_risk():
    payload = {
        "url": "http://192.168.1.50/paypa1-account-login/verify.php"
    }
    res = client.post("/api/analyze-url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_category"] == "High Risk"
    assert data["risk_score"] >= 65
    indicator_ids = [i["id"] for i in data["indicators"]]
    assert "ip_address_host" in indicator_ids or "unencrypted_http" in indicator_ids or "ssrf_private_host" in indicator_ids

def test_analyze_url_legitimate():
    payload = {
        "url": "https://wikipedia.org/wiki/Computer_security"
    }
    res = client.post("/api/analyze-url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_category"] == "Low Risk"
    assert data["risk_score"] <= 35

def test_analyze_content_text_sensational():
    res = client.post("/api/analyze-content/text", json={
        "text": "SHOCKING SECRET: Doctors are FURIOUS that this ancient miracle cure cures all diseases in 24 hours! Share before deleted!!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 50
    assert len(data["indicators"]) >= 1

def test_analyze_content_image():
    # Create small test image
    img = Image.new("RGB", (64, 64), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    
    res = client.post(
        "/api/analyze-content",
        files={"file": ("test_blue.png", buf, "image/png")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "content_image"
    assert "PNG" in data["target_summary"]
    assert "Heuristic" in data["explanation"] or "Forensic" in data["explanation"]

def test_dashboard_and_history():
    res = client.get("/api/dashboard-stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_scans" in stats
    assert "scan_types" in stats
    assert stats["total_scans"] >= 1

    hist_res = client.get("/api/scan-history")
    assert hist_res.status_code == 200
    hist = hist_res.json()
    assert isinstance(hist, list)

def test_empty_input_validation():
    res_msg = client.post("/api/analyze-message", json={"text": ""})
    assert res_msg.status_code == 422
    
    res_url = client.post("/api/analyze-url", json={"url": ""})
    assert res_url.status_code == 422
