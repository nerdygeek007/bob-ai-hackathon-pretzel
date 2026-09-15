"""
ARES Defense Intelligence API Integration Tests
Tests all FastAPI REST endpoints using TestClient.
"""

import pytest
from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)


def test_api_health():
    """Verify /api/health returns healthy status and system metrics."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "ARES" in data["system"]


def test_api_ingest_and_alerts():
    """Verify /api/ingest loads telemetry and /api/alerts returns them."""
    response = client.post("/api/ingest", json={"scenario": "apt_hybrid", "sector": "Sector-4-North"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["new_alerts_ingested"] >= 1

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts_data = alerts_resp.json()
    assert alerts_data["count"] >= 1


def test_api_correlate_and_clusters():
    """Verify /api/correlate groups alerts into clusters."""
    response = client.post("/api/correlate?sector=Sector-4-North")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["incident_clusters_identified"] >= 1

    clusters_resp = client.get("/api/clusters")
    assert clusters_resp.status_code == 200
    clusters_data = clusters_resp.json()
    assert clusters_data["count"] >= 1


def test_api_bluf_and_reports():
    """Verify /api/bluf synthesizes commander report with COAs."""
    response = client.post("/api/bluf")
    assert response.status_code == 200
    data = response.json()
    assert "report_id" in data
    assert "bottom_line_up_front" in data
    assert len(data["wargamed_coas"]) >= 2
    assert data["guardian_assurance"]["verdict"] == "PASSED_DEFENSE_GROUNDING"

    reports_resp = client.get("/api/reports")
    assert reports_resp.status_code == 200
    reports_data = reports_resp.json()
    assert reports_data["count"] >= 1


def test_dashboard_serving():
    """Verify root / serves the Tactical Commander War Room HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "ARES // Commander Tactical War Room" in response.text


def test_api_custom_alerts_ingest():
    """Verify /api/ingest supports custom alerts and file_path."""
    custom_alert = {
        "alert_id": "TEST-CUSTOM-99",
        "timestamp": "2026-09-15T04:30:00Z",
        "domain": "satellite_ew",
        "source_name": "TEST-SAT-01",
        "raw_payload": "Spot-beam RF jamming detected on 14.2 GHz Ku-band uplink with unauthorized Modbus injection.",
        "sector": "Sector-Custom-Test",
        "target_entity": "10.4.1.99",
        "source_ip": "198.51.100.99",
        "destination_ip": "10.4.1.99",
        "event_code": "SAT_JAM_TEST",
        "metadata": {"test": True}
    }

    # 1. Test Ingesting list of custom alerts
    resp = client.post("/api/ingest", json=[custom_alert])
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["new_alerts_ingested"] == 1

    # 2. Correlate custom sector
    corr_resp = client.post("/api/correlate?sector=Sector-Custom-Test")
    assert corr_resp.status_code == 200
    corr_data = corr_resp.json()
    assert corr_data["status"] == "SUCCESS"
    assert corr_data["incident_clusters_identified"] >= 1

    # 3. Generate BLUF
    bluf_resp = client.post("/api/bluf")
    assert bluf_resp.status_code == 200
    bluf_data = bluf_resp.json()
    assert bluf_data["sector"] == "Sector-Custom-Test"
    assert len(bluf_data["wargamed_coas"]) >= 2

