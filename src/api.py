"""
ARES Defense Intelligence REST API Server
FastAPI backend providing endpoints for Multi-Domain Telemetry Ingestion,
Spatio-Temporal Correlation, MITRE ATT&CK Mapping, and BLUF Report Generation.
"""

import os
from typing import List, Optional, Dict, Any, Union
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from src.engine.schemas import RawTelemetryAlert, IncidentCluster, CommanderBlufReport
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


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": "ARES Defense Intelligence Core",
        "version": "1.0.0",
        "active_alerts": len(SESSION_RAW_ALERTS),
        "active_clusters": len(SESSION_CLUSTERS),
        "generated_reports": len(SESSION_REPORTS),
        "ai_connection": mcp_service.bluf_gen.ai_client.get_status()
    }


@app.get("/api/config/ai")
def get_ai_status():
    """Returns the current IBM Granite / watsonx AI connection status."""
    return mcp_service.bluf_gen.ai_client.get_status()


@app.post("/api/ingest")
def ingest_telemetry(payload: Union[IngestRequest, List[RawTelemetryAlert]]):
    """Step 1 & 2: Ingests multi-domain telemetry feeds (SIEM, Satellite, EDR, OSINT, or Custom)."""
    if isinstance(payload, list):
        sec = payload[0].sector if (payload and payload[0].sector) else "Sector-Custom"
        return mcp_service.ingest_telemetry(
            scenario="custom",
            sector=sec,
            custom_alerts=payload,
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
