"""
ARES Defense Intelligence Automated Test Suite
Unit and integration tests covering the complete 5-step threat intelligence pipeline.
"""

import pytest
from src.engine.schemas import RawTelemetryAlert, TelemetryDomain, SeverityLevel
from src.engine.normalizer import TelemetryNormalizer
from src.engine.anti_chaff_filter import AntiChaffFilter
from src.engine.spatio_temporal_graph import SpatioTemporalGraphEngine
from src.data.mitre_attack_loader import MitreAttackKnowledgeBase
from src.ai.mitre_mapper import MitreMapper
from src.ai.bluf_generator import BlufGenerator
from src.mcp_server import AresDefenseMcpService


def test_mitre_knowledge_base_loading():
    """Verify that MITRE ATT&CK techniques load and match keywords correctly."""
    kb = MitreAttackKnowledgeBase()
    assert len(kb.techniques) >= 15
    assert "T1078" in kb.techniques
    assert "T1059" in kb.techniques

    matches = kb.match_technique("powershell.exe -enc Base64 after failed ssh bruteforce")
    technique_ids = [m["technique_id"] for m in matches]
    assert "T1059" in technique_ids or "T1078" in technique_ids


def test_telemetry_normalization_and_provenance():
    """Verify STIX 2.1 normalization and SHA-256 cryptographic hashing."""
    raw = RawTelemetryAlert(
        alert_id="TEST-ALERT-01",
        timestamp="2026-09-14T12:00:00Z",
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="IBM-QRadar",
        raw_payload="CEF:0|IBM|QRadar|1420 failed SSH logins from 198.51.100.44 on Gateway-04",
        source_ip="198.51.100.44",
        target_entity="Gateway-04"
    )

    entity = TelemetryNormalizer.normalize_alert(raw)
    assert entity.original_alert_id == "TEST-ALERT-01"
    assert entity.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    assert len(entity.raw_reference_hash) == 64  # Valid SHA-256 string
    assert any("198.51.100.44" in ioc for ioc in entity.iocs)


def test_anti_chaff_filter():
    """Verify that Shannon Entropy correctly suppresses decoy alert storms."""
    # Create 30 repetitive low-entropy alerts + 1 critical stealth alert
    entities = []
    for i in range(30):
        raw = RawTelemetryAlert(
            alert_id=f"CHAFF-{i}",
            timestamp="2026-09-14T12:00:00Z",
            domain=TelemetryDomain.CYBER_SIEM,
            source_name="Firewall",
            raw_payload="FW_DROP: Inbound port scan dropped."
        )
        entities.append(TelemetryNormalizer.normalize_alert(raw))

    # Add 1 stealth critical alert
    stealth = RawTelemetryAlert(
        alert_id="STEALTH-01",
        timestamp="2026-09-14T12:01:00Z",
        domain=TelemetryDomain.CYBER_EDR,
        source_name="CrowdStrike",
        raw_payload="CRITICAL: Zero-day privilege escalation dirty pipe exploit."
    )
    entities.append(TelemetryNormalizer.normalize_alert(stealth))

    filtered, meta = AntiChaffFilter.filter_chaff(entities)
    assert meta["is_chaff_detected"] is True
    assert meta["suppressed_count"] > 20
    assert any(e.original_alert_id == "STEALTH-01" for e in filtered)


def test_spatio_temporal_graph_correlation():
    """Verify that multi-domain alerts are grouped into prioritized Incident Clusters."""
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    result = service.correlate_alerts("Sector-4-North")

    assert result["status"] == "SUCCESS"
    assert result["incident_clusters_identified"] >= 1
    top_cluster = result["clusters"][0]
    assert top_cluster["severity"] in ["HIGH", "CRITICAL"]


def test_bluf_generation_and_wargamed_coas():
    """Verify military-standard BLUF report synthesis, COAs, and Guardian assurance."""
    service = AresDefenseMcpService()
    service.ingest_telemetry("apt_hybrid", "Sector-4-North")
    service.correlate_alerts("Sector-4-North")
    bluf_res = service.generate_bluf()

    assert "report_id" in bluf_res
    assert "bottom_line_up_front" in bluf_res
    assert len(bluf_res["bottom_line_up_front"]) > 20
    assert len(bluf_res["wargamed_coas"]) >= 2
    assert any(coa["is_recommended"] for coa in bluf_res["wargamed_coas"])
    assert bluf_res["guardian_assurance"]["verdict"] == "PASSED_DEFENSE_GROUNDING"
