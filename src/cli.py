"""
ARES Interactive Defense Command Line Interface (CLI)
Enables defense analysts and commanders to run all 5 workflow steps directly in the terminal:
1. Ingest Multi-Domain Telemetry (SIEM, Satellite, EDR, OSINT, or Custom Data)
2. Normalize to STIX 2.1 & Filter Adversarial Chaff
3. Feed to Spatio-Temporal Knowledge Graph
4. Perform MITRE ATT&CK Mapping & Threat Attribution
5. Generate Military BLUF Briefings with Wargamed COAs
"""

import os
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional, List

# Ensure UTF-8 output encoding on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.engine.schemas import RawTelemetryAlert, TelemetryDomain
from src.mcp_server import AresDefenseMcpService


def print_banner():
    print("=" * 75)
    print("[ARES] DEFENSE THREAT INTELLIGENCE & ALERT PRIORITISATION ASSISTANT")
    print("       Powered by IBM Bob (MCP) & IBM watsonx.ai Granite 3.0")
    print("=" * 75)


def run_pipeline(
    scenario: str = "apt_hybrid",
    sector: str = "Sector-4-North",
    file_path: Optional[str] = None,
    custom_alerts: Optional[List[RawTelemetryAlert]] = None,
    clear_session: bool = True
):
    print_banner()
    service = AresDefenseMcpService()

    source_label = f"File: {file_path}" if file_path else ("Custom Input" if custom_alerts else scenario)
    print(f"\n[STEP 1: INGESTION] Loading multi-domain telemetry ({source_label})...")
    
    ingest_res = service.ingest_telemetry(
        scenario=scenario,
        sector=sector,
        custom_alerts=custom_alerts,
        file_path=file_path,
        clear_session=clear_session
    )
    print(f"    [+] Ingested {ingest_res['new_alerts_ingested']} raw sensor alerts into {ingest_res['sector']}.")

    print(f"\n[STEP 2 & 3: CORRELATION & ANTI-CHAFF] Building Spatio-Temporal Knowledge Graph...")
    corr_res = service.correlate_alerts(sector=ingest_res['sector'])
    print(f"    [+] Processed {corr_res['total_raw_alerts_processed']} alerts.")
    print(f"    [*] Formed {corr_res['incident_clusters_identified']} correlated Incident Clusters.")
    
    if corr_res['incident_clusters_identified'] == 0:
        print("    [!] No incident clusters formed (alerts classified as benign / sub-threshold noise).")
        return

    for idx, c in enumerate(corr_res['clusters'], start=1):
        print(f"       [{idx}] Cluster {c['cluster_id']} | Severity: {c['severity']} | Conf: {c['bayesian_confidence']} | Threat: {c['threat_actor']}")
        print(f"           Stage: {c['stage']} | Domains: {', '.join(c['domains'])}")
        print(f"           Top MITRE: {', '.join(c['top_mitre_techniques'])}")

    print(f"\n[STEP 4 & 5: WATSONX AI ANALYSIS & BLUF SYNTHESIS] Generating Commander Briefing...")
    bluf_res = service.generate_bluf()

    print("\n" + "=" * 75)
    print(f"CLASSIFICATION: {bluf_res['classification']}")
    print(f"REPORT ID: {bluf_res['report_id']} | INCIDENT: {bluf_res['cluster_id']}")
    print(f"SECTOR: {bluf_res['sector']} | SEVERITY: {bluf_res['severity']} | CONFIDENCE: {bluf_res['bayesian_confidence']}")
    print(f"ATTRIBUTION: {bluf_res['threat_actor']}")
    print("-" * 75)
    print("BOTTOM LINE UP FRONT (BLUF):")
    print(f"   {bluf_res['bottom_line_up_front']}")
    print("\nCONFIRMED OPERATIONAL FINDINGS:")
    for f in bluf_res['key_findings']:
        print(f"   * {f}")
    
    print("\nMITRE ATT&CK TECHNIQUES DETECTED:")
    for t in bluf_res['mitre_ttps']:
        print(f"   [{t['id']}] {t['name']} ({t['tactic']}) - Conf: {t['confidence']}")
        print(f"       Mitigation: {t['mitigations'][0] if t['mitigations'] else 'N/A'}")

    print("\nWARGAMED COURSES OF ACTION (COAs):")
    for coa in bluf_res['wargamed_coas']:
        rec_tag = " [RECOMMENDED]" if coa['is_recommended'] else ""
        print(f"   [{coa['option_id']}]{rec_tag} {coa['title']} (Containment: {coa['containment']} | Disruption: {coa['mission_disruption']})")
        print(f"       Tradeoff: {coa['tradeoff']}")

    print("\nWATSONX GRANITE GUARDIAN ASSURANCE:")
    print(f"   Grounding Score: {bluf_res['guardian_assurance']['score']} | Verdict: {bluf_res['guardian_assurance']['verdict']}")
    print("=" * 75)


def interactive_prompt() -> List[RawTelemetryAlert]:
    """Prompts the operator to enter custom alert parameters."""
    print("\n--- Enter Custom Threat Alert Details ---")
    domain_choice = input("Select Domain [1: cyber_siem, 2: cyber_edr, 3: satellite_ew, 4: kinetic_radar] (Default: 1): ").strip()
    domains = {
        "1": TelemetryDomain.CYBER_SIEM,
        "2": TelemetryDomain.CYBER_EDR,
        "3": TelemetryDomain.SATELLITE_EW,
        "4": TelemetryDomain.KINETIC_RADAR
    }
    domain = domains.get(domain_choice, TelemetryDomain.CYBER_SIEM)

    source_name = input("Sensor/Source Name (e.g. QRadar-GW, SAT-01, CrowdStrike) [CustomSensor]: ").strip() or "CustomSensor"
    sector = input("Operational Sector [Sector-Custom]: ").strip() or "Sector-Custom"
    target_ip = input("Target / Destination IP [10.4.1.50]: ").strip() or "10.4.1.50"
    source_ip = input("Adversary Source IP [198.51.100.88]: ").strip() or "198.51.100.88"
    raw_payload = input("Raw Alert / Log Message: ").strip() or "Unauthorized PowerShell execution detected attempting Modbus write."

    now_iso = datetime.now(timezone.utc).isoformat()
    alert = RawTelemetryAlert(
        alert_id=f"CUSTOM-{int(datetime.now().timestamp())}",
        timestamp=now_iso,
        domain=domain,
        source_name=source_name,
        raw_payload=raw_payload,
        sector=sector,
        target_entity=target_ip,
        source_ip=source_ip,
        destination_ip=target_ip,
        event_code="CUSTOM_INPUT",
        metadata={"operator_injected": True}
    )
    return [alert]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARES Defense Threat Intelligence CLI")
    parser.add_argument(
        "--scenario",
        default="apt_hybrid",
        choices=["apt_hybrid", "chaff_flood", "benign", "custom", "real_ephemeris"],
        help="Telemetry scenario or 'real_ephemeris' for CelesTrak NORAD satellite telemetry"
    )
    parser.add_argument("--sector", default=None, help="Operational sector (defaults by scenario)")
    parser.add_argument("--satellite", help="Target satellite name or NORAD Cat ID (for real_ephemeris scenario)")
    parser.add_argument("--sat-catalog", action="store_true", help="Display tracked defense satellites from CelesTrak NORAD catalog")
    parser.add_argument("--file", help="Path to a custom JSON or JSONL file of alerts")
    parser.add_argument("--interactive", action="store_true", help="Interactively input custom alert details")
    args = parser.parse_args()

    if args.sat_catalog:
        print_banner()
        service = AresDefenseMcpService()
        catalog = service.get_satellite_ephemeris()
        print(f"\nAuthoritative CelesTrak NORAD Satellite Catalog ({len(catalog)} Tracked Defense Assets):")
        print("-" * 75)
        print(f"{'NORAD ID':<10} {'NAME':<24} {'ORBIT':<8} {'ALTITUDE':<12} {'PERIOD':<10} {'INCLINATION'}")
        print("-" * 75)
        for sat in catalog[:15]:
            print(f"{sat['norad_cat_id']:<10} {sat['object_name']:<24} {sat['orbit_type']:<8} {str(sat['altitude_km']) + ' km':<12} {str(sat['period_minutes']) + ' min':<10} {sat['inclination_deg']}°")
        if len(catalog) > 15:
            print(f"... and {len(catalog) - 15} more satellites tracked.")
        print("-" * 75)
        sys.exit(0)

    effective_sector = args.sector
    if not effective_sector:
        effective_sector = "Sector-Space-LEO" if args.scenario == "real_ephemeris" else "Sector-4-North"

    if args.interactive:
        alerts = interactive_prompt()
        run_pipeline(custom_alerts=alerts, sector=alerts[0].sector or effective_sector)
    elif args.file:
        run_pipeline(file_path=args.file, sector=effective_sector)
    elif args.scenario == "custom":
        custom_file = os.path.join(os.path.dirname(__file__), "data", "sample_custom_alerts.json")
        run_pipeline(file_path=custom_file, sector=effective_sector)
    elif args.scenario == "real_ephemeris":
        service = AresDefenseMcpService()
        alerts = service.ephemeris_client.generate_satellite_anomaly_alerts(
            sector=effective_sector,
            satellite_query=args.satellite or "SAR-LUPE"
        )
        run_pipeline(custom_alerts=alerts, sector=effective_sector)
    else:
        run_pipeline(scenario=args.scenario, sector=effective_sector)
