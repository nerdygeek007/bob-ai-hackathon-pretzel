"""
MITRE ATT&CK FastMCP Integration Server
========================================
Exposes the `map_mitre_technique` MCP tool so that IBM Bob and other
MCP-aware clients can invoke MITRE RAG mapping as part of automated
workflow runs without calling the FastAPI endpoint directly.

Usage:
    python mitre_mcp_server.py

The server starts an MCP-over-stdio transport by default, which is what
Bob expects.  Set MCP_TRANSPORT=sse to start an HTTP/SSE server instead
(useful for remote deployments).

Environment variables:
    MITRE_API_BASE_URL  – Base URL of the running FastAPI backend
                          (default: http://localhost:8000)
    MCP_TRANSPORT       – "stdio" (default) or "sse"
    MCP_SSE_HOST        – Host for SSE mode (default: 0.0.0.0)
    MCP_SSE_PORT        – Port for SSE mode (default: 8001)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

try:
    from mcp.server import FastMCP  # fastmcp >= 2.0
except ImportError:
    raise ImportError(
        "fastmcp is not installed.  Run: pip install fastmcp"
    )

logger = logging.getLogger("mitre_mcp_server")
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MITRE_API_BASE = os.getenv("MITRE_API_BASE_URL", "http://localhost:8000")
MCP_TRANSPORT = os.getenv("MCP_TRANSPORT", "stdio")
MCP_SSE_HOST = os.getenv("MCP_SSE_HOST", "0.0.0.0")
MCP_SSE_PORT = int(os.getenv("MCP_SSE_PORT", "8001"))

# ---------------------------------------------------------------------------
# MCP server definition
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="mitre-attack-rag",
    description=(
        "Maps security alert clusters to MITRE ATT&CK v15 Enterprise techniques "
        "using vector search (ChromaDB) and optional watsonx.ai LLM re-ranking."
    ),
)


# ---------------------------------------------------------------------------
# Tool: map_mitre_technique
# ---------------------------------------------------------------------------
@mcp.tool(
    description=(
        "Map an alert cluster or incident summary to the most relevant MITRE ATT&CK "
        "technique.  Returns technique_id, technique_name, tactic, confidence_score "
        "(0-100), and a list of evidence strings."
    )
)
def map_mitre_technique(
    cluster_id: str,
    summary: str,
    alert_titles: Optional[List[str]] = None,
    indicators: Optional[List[str]] = None,
    tactic_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parameters
    ----------
    cluster_id   : Unique identifier for the alert cluster or incident.
    summary      : Free-form prose description of the correlated alerts.
    alert_titles : (optional) List of individual alert/event titles.
    indicators   : (optional) IOCs such as IPs, domains, hashes, usernames.
    tactic_hint  : (optional) Suspected MITRE tactic (e.g. 'Lateral Movement').

    Returns
    -------
    dict with keys: technique_id, technique_name, tactic, confidence_score, evidence
    """
    payload: Dict[str, Any] = {
        "cluster_id": cluster_id,
        "summary": summary,
        "alert_titles": alert_titles or [],
        "indicators": indicators or [],
    }
    if tactic_hint:
        payload["tactic_hint"] = tactic_hint

    try:
        resp = httpx.post(
            f"{MITRE_API_BASE}/api/mitre/map",
            json=payload,
            timeout=45,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300]
        raise RuntimeError(f"MITRE API returned {exc.response.status_code}: {detail}") from exc
    except httpx.RequestError as exc:
        raise RuntimeError(
            f"Could not reach MITRE API at {MITRE_API_BASE}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Tool: get_technique_description
# ---------------------------------------------------------------------------
@mcp.tool(
    description=(
        "Return the human-readable description and tactic for a known MITRE ATT&CK "
        "technique ID (e.g. T1059.001). Useful for enriching reports."
    )
)
def get_technique_description(technique_id: str) -> Dict[str, Any]:
    """
    Parameters
    ----------
    technique_id : MITRE technique ID string, e.g. 'T1059.001'.

    Returns
    -------
    dict with keys: id, name, tactic, description  – or an error string.
    """
    # Inline lookup from the same seed data so this tool works without a running
    # backend.  Kept intentionally minimal.
    from mitre_rag_agent import MITRE_SEED  # type: ignore[import]

    match = next((t for t in MITRE_SEED if t["id"] == technique_id), None)
    if match:
        return {
            "id": match["id"],
            "name": match["name"],
            "tactic": match["tactic"],
            "description": match["description"],
        }
    return {"error": f"Technique {technique_id!r} not found in local seed data."}


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if MCP_TRANSPORT == "sse":
        logger.info("Starting MITRE MCP server (SSE) on %s:%s", MCP_SSE_HOST, MCP_SSE_PORT)
        mcp.run(transport="sse", host=MCP_SSE_HOST, port=MCP_SSE_PORT)
    else:
        logger.info("Starting MITRE MCP server (stdio)")
        mcp.run(transport="stdio")
