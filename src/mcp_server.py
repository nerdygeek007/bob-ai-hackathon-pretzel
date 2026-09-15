"""
ARES IBM Bob Model Context Protocol (MCP) Server
Exposes defense intelligence tools directly to IBM Bob CLI and IDE:
- ingest_telemetry_feed: Ingests multi-domain alerts (SIEM, Satellite, EDR)
- correlate_threat_alerts: Performs Spatio-Temporal Knowledge Graph correlation
- generate_commander_bluf: Produces structured military BLUF briefings
- map_to_mitre_attack: Maps observed techniques to MITRE ATT&CK matrix
- simulate_defense_coa: Wargames defensive courses of action
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.engine.schemas import RawTelemetryAlert, TelemetryDomain, IncidentCluster, CommanderBlufReport
from src.engine.normalizer import TelemetryNormalizer
from src.engine.spatio_temporal_graph import SpatioTemporalGraphEngine
from src.data.synthetic_scenarios import (
    generate_apt_hybrid_campaign,
    generate_adversarial_chaff_flood,
    generate_benign_background_noise
)
from src.ai.mitre_mapper import MitreMapper
from src.ai.bluf_generator import BlufGenerator
from src.ai.watsonx_client import WatsonxClient

# In-memory storage for active session state
SESSION_RAW_ALERTS: List[RawTelemetryAlert] = []
SESSION_CLUSTERS: Dict[str, IncidentCluster] = {}
SESSION_REPORTS: Dict[str, CommanderBlufReport] = {}


class AresDefenseMcpService:
    """Core logic exposed to IBM Bob MCP Server."""

    def __init__(self):
        self.normalizer = TelemetryNormalizer()
        self.graph_engine = SpatioTemporalGraphEngine()
        self.mitre_mapper = MitreMapper()
        self.bluf_gen = BlufGenerator()

    def ingest_telemetry(
        self,
        scenario: str = "apt_hybrid",
        sector: str = "Sector-4-North",
        custom_alerts: Optional[List[RawTelemetryAlert]] = None,
        file_path: Optional[str] = None,
        clear_session: bool = False
    ) -> Dict[str, Any]:
        """Ingests multi-domain telemetry feeds into the active session."""
        global SESSION_RAW_ALERTS, SESSION_CLUSTERS, SESSION_REPORTS

        if clear_session:
            SESSION_RAW_ALERTS.clear()
            SESSION_CLUSTERS.clear()
            SESSION_REPORTS.clear()

        alerts: List[RawTelemetryAlert] = []

        if custom_alerts:
            alerts = custom_alerts
        elif file_path:
            import os
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Custom telemetry file not found: {file_path}")
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content.startswith("["):
                    data = json.loads(content)
                    alerts = [RawTelemetryAlert(**item) for item in data]
                else:
                    for line in content.splitlines():
                        if line.strip():
                            alerts.append(RawTelemetryAlert(**json.loads(line)))
        elif scenario == "chaff_flood":
            alerts = generate_adversarial_chaff_flood(sector=sector, count=40)
        elif scenario == "benign":
            alerts = generate_benign_background_noise(sector=sector)
        else:
            alerts = generate_apt_hybrid_campaign(sector=sector)

        SESSION_RAW_ALERTS.extend(alerts)

        effective_sector = alerts[0].sector if (alerts and alerts[0].sector) else sector

        return {
            "status": "SUCCESS",
            "scenario_loaded": "custom" if (custom_alerts or file_path) else scenario,
            "sector": effective_sector,
            "new_alerts_ingested": len(alerts),
            "total_alerts_in_session": len(SESSION_RAW_ALERTS),
            "sample_alert_ids": [a.alert_id for a in alerts[:5]]
        }

    def correlate_alerts(self, sector: Optional[str] = None) -> Dict[str, Any]:
        """Runs the Spatio-Temporal Knowledge Graph & Anti-Chaff Correlation Engine."""
        global SESSION_RAW_ALERTS, SESSION_CLUSTERS

        target_sector = sector
        if not target_sector and SESSION_RAW_ALERTS:
            target_sector = SESSION_RAW_ALERTS[0].sector or "Sector-4-North"
        elif not target_sector:
            target_sector = "Sector-4-North"

        if not SESSION_RAW_ALERTS:
            # Auto-ingest default scenario if empty
            self.ingest_telemetry("apt_hybrid", target_sector)

        # 1. Normalize
        normalized = self.normalizer.normalize_batch(SESSION_RAW_ALERTS)

        # 2. Correlate
        clusters = self.graph_engine.correlate_alerts(normalized, sector=target_sector)

        SESSION_CLUSTERS.clear()
        cluster_summaries = []

        for c in clusters:
            # Map MITRE techniques
            c.mitre_techniques = self.mitre_mapper.map_cluster_techniques(c)
            SESSION_CLUSTERS[c.cluster_id] = c

            cluster_summaries.append({
                "cluster_id": c.cluster_id,
                "severity": c.overall_severity.value,
                "bayesian_confidence": f"{int(c.bayesian_threat_confidence * 100)}%",
                "threat_actor": c.primary_threat_actor,
                "alert_count": c.alert_count,
                "domains": [d.value for d in c.domains_involved],
                "stage": c.attack_lifecycle_stage,
                "top_mitre_techniques": [t.technique_id + " (" + t.name + ")" for t in c.mitre_techniques[:3]]
            })

        return {
            "status": "SUCCESS",
            "total_raw_alerts_processed": len(SESSION_RAW_ALERTS),
            "incident_clusters_identified": len(clusters),
            "clusters": cluster_summaries
        }

    def generate_bluf(self, cluster_id: Optional[str] = None) -> Dict[str, Any]:
        """Generates a military-standard BLUF briefing for an incident cluster."""
        global SESSION_CLUSTERS, SESSION_REPORTS

        if not SESSION_CLUSTERS:
            self.correlate_alerts()

        # Select specified cluster or highest priority cluster
        target_cluster = None
        if cluster_id and cluster_id in SESSION_CLUSTERS:
            target_cluster = SESSION_CLUSTERS[cluster_id]
        elif SESSION_CLUSTERS:
            target_cluster = list(SESSION_CLUSTERS.values())[0]

        if not target_cluster:
            return {"error": "No incident cluster found."}

        report = self.bluf_gen.generate_bluf_report(target_cluster)
        SESSION_REPORTS[report.report_id] = report

        return {
            "report_id": report.report_id,
            "classification": report.classification_level,
            "cluster_id": report.cluster_id,
            "sector": report.sector,
            "severity": report.severity.value,
            "bayesian_confidence": f"{int(report.bayesian_confidence * 100)}%",
            "threat_actor": report.threat_actor_attribution,
            "bottom_line_up_front": report.bottom_line_up_front,
            "key_findings": report.key_findings,
            "mitre_ttps": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "confidence": f"{int(t.confidence * 100)}%",
                    "mitigations": t.mitigations
                }
                for t in report.mitre_ttps
            ],
            "wargamed_coas": [
                {
                    "option_id": coa.option_id,
                    "title": coa.title,
                    "containment": f"{int(coa.containment_efficacy * 100)}%",
                    "mission_disruption": coa.mission_disruption_impact,
                    "is_recommended": coa.is_recommended,
                    "tradeoff": coa.tradeoff_summary
                }
                for coa in report.wargamed_coas
            ],
            "guardian_assurance": {
                "score": report.guardian_grounding_score,
                "verdict": report.guardian_verdict
            },
            "provenance_citations": [
                {
                    "claim_index": c.claim_index,
                    "sensor_id": c.source_alert_id,
                    "timestamp": c.source_timestamp,
                    "sha256_hash": c.sha256_hash[:16] + "..."
                }
                for c in report.provenance_citations
            ]
        }


# MCP Tool Definitions for IBM Bob
TOOLS_REGISTRY = [
    {
        "name": "ares_ingest_telemetry",
        "description": "Ingests multi-domain defense alerts (SIEM CEF, Satellite RF, EDR process logs, OSINT, or Custom file).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scenario": {
                    "type": "string",
                    "enum": ["apt_hybrid", "chaff_flood", "benign", "custom"],
                    "description": "Scenario to ingest"
                },
                "sector": {
                    "type": "string",
                    "description": "Operational sector"
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional path to custom JSON alerts file"
                }
            }
        }
    },
    {
        "name": "ares_correlate_threats",
        "description": "Correlates multi-domain telemetry using a Spatio-Temporal Knowledge Graph and suppresses chaff.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sector": {
                    "type": "string",
                    "description": "Sector to analyze"
                }
            }
        }
    },
    {
        "name": "ares_generate_bluf",
        "description": "Synthesizes military-standard BLUF briefings with MITRE ATT&CK mapping and wargamed COAs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cluster_id": {
                    "type": "string",
                    "description": "Optional specific cluster ID"
                }
            }
        }
    }
]


def run_stdio_mcp_server():
    """Runs a standard Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for IBM Bob."""
    service = AresDefenseMcpService()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            if method == "initialize":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "ares-defense-mcp",
                            "version": "1.0.0"
                        }
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()

            elif method == "notifications/initialized":
                pass

            elif method == "ping":
                res = {"jsonrpc": "2.0", "id": req_id, "result": {}}
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()

            elif method == "tools/list":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": TOOLS_REGISTRY
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()

            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})

                if tool_name == "ares_ingest_telemetry":
                    output = service.ingest_telemetry(
                        scenario=args.get("scenario", "apt_hybrid"),
                        sector=args.get("sector", "Sector-4-North"),
                        file_path=args.get("file_path")
                    )
                elif tool_name == "ares_correlate_threats":
                    output = service.correlate_alerts(sector=args.get("sector"))
                elif tool_name == "ares_generate_bluf":
                    output = service.generate_bluf(cluster_id=args.get("cluster_id"))
                else:
                    output = {"error": f"Unknown tool: {tool_name}"}

                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(output, indent=2)
                            }
                        ]
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()

            else:
                if req_id is not None:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}"
                        }
                    }
                    sys.stdout.write(json.dumps(res) + "\n")
                    sys.stdout.flush()

        except Exception as e:
            req_id = req.get("id") if "req" in locals() and isinstance(req, dict) else None
            if req_id is not None:
                err_res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": str(e)
                    }
                }
                sys.stdout.write(json.dumps(err_res) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        service = AresDefenseMcpService()
        print("=== ARES IBM Bob MCP Server Initialized ===")
        print("Available Tools:", [t["name"] for t in TOOLS_REGISTRY])
        ingest_res = service.ingest_telemetry("apt_hybrid", "Sector-4-North")
        print(f"\n[1. Ingest]: {ingest_res['new_alerts_ingested']} alerts loaded.")
        corr_res = service.correlate_alerts("Sector-4-North")
        print(f"[2. Correlate]: {corr_res['incident_clusters_identified']} incident clusters formed.")
        bluf_res = service.generate_bluf()
        print(f"[3. BLUF Generated]: {bluf_res['report_id']}")
        print(f"\nBLUF: {bluf_res['bottom_line_up_front']}")
    else:
        run_stdio_mcp_server()
