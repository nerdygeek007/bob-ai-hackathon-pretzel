"""
ARES Defense Intelligence REST API Server
FastAPI backend providing endpoints for Multi-Domain Telemetry Ingestion,
Spatio-Temporal Correlation, MITRE ATT&CK Mapping, and BLUF Report Generation.
"""

import os
import json
import uuid
from typing import List, Optional, Dict, Any, Union
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from src.engine.schemas import RawTelemetryAlert, TelemetryDomain, IncidentCluster, CommanderBlufReport
from src.ai.report_exporter import ReportExporter
from src.mcp_server import AresDefenseMcpService, SESSION_RAW_ALERTS, SESSION_CLUSTERS, SESSION_REPORTS

app = FastAPI(
    title="ARES Defense Threat Intelligence API",
    description="Multi-Domain Correlation, False Positive Mitigation & Military BLUF Generator",
    version="1.0.0"
)

# Enable CORS for dashboard and local tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

mcp_service = AresDefenseMcpService()


class IngestRequest(BaseModel):
    scenario: str = "apt_hybrid"
    sector: str = "Sector-4-North"
    custom_alerts: Optional[List[RawTelemetryAlert]] = None
    file_path: Optional[str] = None
    clear_session: bool = False


class SimulateRequest(BaseModel):
    count: int = 25
    scenario: str = "apt_hybrid"
    sector: str = "Sector-4-North"


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": "ARES Defense Intelligence Core",
        "version": "1.0.0",
        "active_alerts": len(SESSION_RAW_ALERTS),
        "active_clusters": len(SESSION_CLUSTERS),
        "generated_reports": len(SESSION_REPORTS),
        "satellites_tracked": len(mcp_service.get_satellite_ephemeris()),
        "ai_connection": mcp_service.bluf_gen.ai_client.get_status()
    }


@app.get("/api/config/ai")
def get_ai_status():
    """Returns the current IBM Granite / watsonx AI connection status."""
    return mcp_service.bluf_gen.ai_client.get_status()


@app.get("/api/satellites/ephemeris")
def get_satellite_ephemeris(query: Optional[str] = Query(None)):
    """Returns authoritative CelesTrak / NORAD satellite ephemeris, altitude, period, and orbital class."""
    satellites = mcp_service.get_satellite_ephemeris(query=query)
    return {
        "source": "CelesTrak NORAD Open Catalog",
        "count": len(satellites),
        "satellites": satellites
    }


@app.post("/api/simulate")
def simulate_telemetry(req: SimulateRequest):
    """Generates and streams simulated heterogeneous SIEM and tactical telemetry (QRadar, EDR, OCSF, CoT)."""
    return mcp_service.simulate_siem(
        count=req.count,
        scenario=req.scenario,
        sector=req.sector
    )


@app.post("/api/ingest")
def ingest_telemetry(payload: Union[IngestRequest, List[Dict[str, Any]], List[RawTelemetryAlert]]):
    """Step 1 & 2: Ingests multi-domain telemetry feeds (SIEM, Satellite, EDR, OSINT, OCSF, CoT, or Custom)."""
    if isinstance(payload, list):
        parsed_alerts: List[RawTelemetryAlert] = []
        for item in payload:
            if isinstance(item, RawTelemetryAlert):
                parsed_alerts.append(item)
            elif isinstance(item, dict):
                if "class_uid" in item:
                    # OCSF v1.1 Finding
                    parsed_alerts.append(RawTelemetryAlert(
                        alert_id=item.get("finding_info", {}).get("uid", f"OCSF-{uuid.uuid4().hex[:6].upper()}"),
                        timestamp=item.get("time", "2026-09-15T12:00:00Z"),
                        domain=TelemetryDomain.OCSF_SECURITY,
                        source_name="OCSF v1.1 Ingestion",
                        event_code=item.get("metadata", {}).get("event_code", "OCSF_FINDING"),
                        raw_payload=json.dumps(item),
                        target_entity=item.get("device", {}).get("hostname"),
                        sector="Sector-4-North"
                    ))
                elif "lat" in item and ("lon" in item or "uid" in item):
                    # CoT Telemetry
                    parsed_alerts.append(RawTelemetryAlert(
                        alert_id=item.get("uid", f"COT-{uuid.uuid4().hex[:6].upper()}"),
                        timestamp=item.get("time", "2026-09-15T12:00:00Z"),
                        domain=TelemetryDomain.TACTICAL_COT,
                        source_name="Cursor-on-Target Feed",
                        event_code=item.get("type", "a-h-G"),
                        raw_payload=json.dumps(item),
                        target_entity=item.get("uid"),
                        sector="Sector-4-North"
                    ))
                elif "raw_payload" in item:
                    parsed_alerts.append(RawTelemetryAlert(**item))
                else:
                    parsed_alerts.append(RawTelemetryAlert(
                        alert_id=item.get("alert_id", f"ALERT-{uuid.uuid4().hex[:6].upper()}"),
                        timestamp=item.get("timestamp", "2026-09-15T12:00:00Z"),
                        domain=TelemetryDomain(item.get("domain", "cyber_siem")),
                        source_name=item.get("source_name", "generic_siem"),
                        raw_payload=json.dumps(item),
                        sector=item.get("sector", "Sector-4-North")
                    ))
        sec = parsed_alerts[0].sector if (parsed_alerts and parsed_alerts[0].sector) else "Sector-Custom"
        return mcp_service.ingest_telemetry(
            scenario="custom",
            sector=sec,
            custom_alerts=parsed_alerts,
            clear_session=False
        )
    return mcp_service.ingest_telemetry(
        scenario=payload.scenario,
        sector=payload.sector,
        custom_alerts=payload.custom_alerts,
        file_path=payload.file_path,
        clear_session=payload.clear_session
    )


@app.get("/api/alerts")
def get_alerts():
    """Returns raw and normalized alerts in the active session."""
    return {
        "count": len(SESSION_RAW_ALERTS),
        "alerts": [a.model_dump() for a in SESSION_RAW_ALERTS]
    }


@app.post("/api/correlate")
def correlate_threats(sector: str = Query("Sector-4-North")):
    """Step 2 & 4: Runs Spatio-Temporal Graph correlation, anti-chaff filtering, and MITRE mapping."""
    return mcp_service.correlate_alerts(sector=sector)


@app.get("/api/clusters")
def get_clusters():
    """Returns active incident clusters."""
    if not SESSION_CLUSTERS:
        mcp_service.correlate_alerts()
    return {
        "count": len(SESSION_CLUSTERS),
        "clusters": [c.model_dump() for c in SESSION_CLUSTERS.values()]
    }


@app.post("/api/bluf")
def generate_bluf(cluster_id: Optional[str] = Query(None)):
    """Step 4 & 5: Generates military-standard BLUF briefing with wargamed COAs and Granite Guardian assurance."""
    return mcp_service.generate_bluf(cluster_id=cluster_id)


@app.get("/api/reports")
def get_reports():
    """Returns all generated commander BLUF reports."""
    return {
        "count": len(SESSION_REPORTS),
        "reports": [r.model_dump() for r in SESSION_REPORTS.values()]
    }


class ExportReportRequest(BaseModel):
    report_id: Optional[str] = None
    format: str = "markdown"  # markdown | html | json | text | all
    output_dir: str = "reports"


@app.get("/api/reports/export")
def export_report_get(
    report_id: Optional[str] = Query(None),
    format: str = Query("markdown"),
    download: bool = Query(False)
):
    """Exports the latest or specified BLUF report in Markdown, HTML, JSON, or Text format."""
    target_report = None
    if report_id and report_id in SESSION_REPORTS:
        target_report = SESSION_REPORTS[report_id]
    elif SESSION_REPORTS:
        target_report = list(SESSION_REPORTS.values())[-1]
    else:
        bluf_dict = mcp_service.generate_bluf()
        target_report = SESSION_REPORTS.get(bluf_dict.get("report_id"))

    if not target_report:
        raise HTTPException(status_code=404, detail="No BLUF report available to export.")

    fmt_lower = format.lower()
    if fmt_lower in ["html", "htm"]:
        content = ReportExporter.to_html(target_report)
        media_type = "text/html"
        ext = "html"
    elif fmt_lower == "json":
        content = ReportExporter.to_json(target_report)
        media_type = "application/json"
        ext = "json"
    elif fmt_lower in ["text", "txt"]:
        content = ReportExporter.to_text(target_report)
        media_type = "text/plain"
        ext = "txt"
    else:
        content = ReportExporter.to_markdown(target_report)
        media_type = "text/markdown"
        ext = "md"

    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{target_report.report_id}.{ext}"'

    return Response(content=content, media_type=media_type, headers=headers)


@app.post("/api/reports/export")
def export_report_post(req: ExportReportRequest):
    """Saves the BLUF report directly to disk in the specified format (markdown, html, json, text, or all)."""
    target_report = None
    if req.report_id and req.report_id in SESSION_REPORTS:
        target_report = SESSION_REPORTS[req.report_id]
    elif SESSION_REPORTS:
        target_report = list(SESSION_REPORTS.values())[-1]
    else:
        bluf_dict = mcp_service.generate_bluf()
        target_report = SESSION_REPORTS.get(bluf_dict.get("report_id"))

    if not target_report:
        raise HTTPException(status_code=404, detail="No BLUF report available to export.")

    result = ReportExporter.export_report(
        report=target_report,
        format=req.format,
        output_dir=req.output_dir
    )
    return result


class BobTaskRequest(BaseModel):
    prompt: Optional[str] = "You are ARES Defense Intelligence Assistant. Ingest telemetry for scenario 'apt_hybrid' and generate a commander BLUF report."
    max_turns: int = 1


@app.post("/api/bob/live-run")
def run_live_bob(req: BobTaskRequest):
    """Executes a live reasoning task on IBM Bob CLI using the user's BOB_API_KEY."""
    from src.ai.bob_live_agent import run_bob_task
    result = run_bob_task(prompt=req.prompt, max_turns=req.max_turns)
    return result


# Mount static dashboard files if present
dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/")
    def serve_dashboard():
        index_path = os.path.join(dashboard_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "ARES API Active. Open /docs for Swagger UI."}
