"""
Unit and Integration Tests for ARES Commander BLUF Report Exporter.
Validates Markdown, HTML, JSON, and ASCII Text generation, disk writing,
REST API export endpoints, and MCP tool invocations.
"""

import os
import json
import shutil
import pytest
from fastapi.testclient import TestClient

from src.ai.report_exporter import ReportExporter
from src.mcp_server import AresDefenseMcpService
from src.api import app


client = TestClient(app)
TEST_EXPORT_DIR = "reports/test_exports"


@pytest.fixture(autouse=True)
def cleanup_test_dir():
    yield
    if os.path.exists(TEST_EXPORT_DIR):
        shutil.rmtree(TEST_EXPORT_DIR, ignore_errors=True)


def test_markdown_export():
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    bluf_data = service.generate_bluf()

    md = ReportExporter.to_markdown(bluf_data)
    assert "# SECRET // NOFORN // EXERCISE" in md
    assert "### 1. BOTTOM LINE UP FRONT (BLUF)" in md
    assert "### 2. KEY OPERATIONAL FINDINGS" in md
    assert "### 3. EXPLAINABLE AI (XAI) DECISION DRIVERS" in md
    assert "### 4. MITRE ATT&CK MATRIX MAPPING" in md
    assert "### 5. WARGAMED DEFENSIVE COURSES OF ACTION (COAs)" in md
    assert "### 6. CRYPTOGRAPHIC SENSOR PROVENANCE & AUDIT TRAIL" in md
    assert "### 7. AI GOVERNANCE & FACTUAL ASSURANCE" in md
    assert bluf_data["report_id"] in md


def test_html_export():
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    bluf_data = service.generate_bluf()

    html = ReportExporter.to_html(bluf_data)
    assert "<!DOCTYPE html>" in html
    assert "@media print" in html
    assert "1. Bottom Line Up Front (BLUF)" in html
    assert "Explainable AI (XAI) Decision Drivers" in html
    assert "MITRE ATT&CK Matrix Mapping" in html
    assert "Wargamed Defensive Courses of Action" in html
    assert "Cryptographic Sensor Provenance" in html
    assert bluf_data["report_id"] in html


def test_json_export():
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    bluf_data = service.generate_bluf()

    json_str = ReportExporter.to_json(bluf_data)
    parsed = json.loads(json_str)
    assert parsed["report_id"] == bluf_data["report_id"]
    assert "bottom_line_up_front" in parsed
    assert "mitre_ttps" in parsed
    assert "wargamed_coas" in parsed


def test_text_export():
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    bluf_data = service.generate_bluf()

    txt = ReportExporter.to_text(bluf_data)
    assert "ARES COMMANDER THREAT INTELLIGENCE BRIEFING (BLUF)" in txt
    assert bluf_data["report_id"] in txt
    assert "1. BOTTOM LINE UP FRONT (BLUF):" in txt


def test_export_report_to_disk():
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    bluf_data = service.generate_bluf()

    res = ReportExporter.export_report(
        report=bluf_data,
        format="all",
        output_dir=TEST_EXPORT_DIR
    )
    assert res["status"] == "SUCCESS"
    assert len(res["files"]) == 4
    for fmt in ["markdown", "html", "json", "text"]:
        assert fmt in res["files"]
        fpath = res["files"][fmt]["file_path"]
        assert os.path.exists(fpath)
        assert os.path.getsize(fpath) > 100


def test_api_export_get():
    # Ingest and generate bluf first
    client.post("/api/ingest", json={"scenario": "apt_hybrid", "sector": "Sector-4-North"})
    client.post("/api/correlate?sector=Sector-4-North")
    client.post("/api/bluf")

    # Test markdown export download
    res_md = client.get("/api/reports/export?format=markdown&download=true")
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["Content-Type"]
    assert "attachment; filename=" in res_md.headers.get("Content-Disposition", "")
    assert "BOTTOM LINE UP FRONT" in res_md.text

    # Test html export
    res_html = client.get("/api/reports/export?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["Content-Type"]
    assert "<!DOCTYPE html>" in res_html.text

    # Test json export
    res_json = client.get("/api/reports/export?format=json")
    assert res_json.status_code == 200
    data = res_json.json()
    assert "report_id" in data


def test_api_export_post():
    client.post("/api/ingest", json={"scenario": "apt_hybrid", "sector": "Sector-4-North"})
    client.post("/api/correlate?sector=Sector-4-North")
    client.post("/api/bluf")

    res = client.post("/api/reports/export", json={
        "format": "all",
        "output_dir": TEST_EXPORT_DIR
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert len(data["files"]) == 4


def test_mcp_export_tool():
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    service.generate_bluf()

    mcp_res = service.export_bluf_report(format="markdown", output_dir=TEST_EXPORT_DIR)
    assert mcp_res["status"] == "SUCCESS"
    assert "markdown" in mcp_res["files"]
