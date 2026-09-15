"""
Unit and Integration Tests for ARES SIEM & Multi-Source Telemetry Simulator,
OCSF v1.1, Cursor-on-Target (CoT), and Explainable AI (XAI) Feature Attribution.
"""

import json
import pytest
from fastapi.testclient import TestClient

from src.data.siem_simulator import SiemSimulator
from src.engine.schemas import (
    TelemetryDomain,
    SeverityLevel,
    OCSFSecurityFinding,
    CoTTelemetry,
    XAiExplanation
)
from src.engine.normalizer import TelemetryNormalizer
from src.engine.spatio_temporal_graph import SpatioTemporalGraphEngine
from src.mcp_server import AresDefenseMcpService
from src.api import app


client = TestClient(app)


def test_qradar_cef_generation():
    sim = SiemSimulator(sector="Sector-4-North")
    alert = sim.generate_qradar_cef(is_malicious=True)
    assert alert.domain == TelemetryDomain.CYBER_SIEM
    assert alert.source_name == "IBM QRadar SIEM"
    assert "CEF:0|IBM|QRadar|" in alert.raw_payload
    assert alert.source_ip is not None
    assert alert.sector == "Sector-4-North"

    # Test normalization
    norm = TelemetryNormalizer.normalize_alert(alert)
    assert norm.entity_type == "observed-data"
    assert norm.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM]
    assert len(norm.raw_reference_hash) == 64  # SHA-256 hash


def test_edr_process_generation():
    sim = SiemSimulator(sector="Sector-4-North")
    alert = sim.generate_edr_process(is_malicious=True)
    assert alert.domain == TelemetryDomain.CYBER_EDR
    assert "CrowdStrike" in alert.source_name
    payload = json.loads(alert.raw_payload)
    assert "process_name" in payload
    assert "sha256" in payload

    norm = TelemetryNormalizer.normalize_alert(alert)
    assert any("process:" in ioc for ioc in norm.iocs)


def test_suricata_syslog_generation():
    sim = SiemSimulator(sector="Sector-4-North")
    alert = sim.generate_suricata_syslog(is_malicious=True)
    assert alert.domain == TelemetryDomain.CYBER_SIEM
    assert "suricata" in alert.raw_payload
    assert "<134>1" in alert.raw_payload

    norm = TelemetryNormalizer.normalize_alert(alert)
    assert norm.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]


def test_ocsf_generation_and_normalization():
    sim = SiemSimulator(sector="Sector-4-North")
    ocsf_dict = sim.generate_ocsf_finding(is_malicious=True)
    assert ocsf_dict["class_uid"] == 2001
    assert ocsf_dict["severity_id"] == 5

    # Test Pydantic schema validation
    ocsf_obj = OCSFSecurityFinding(**ocsf_dict)
    assert ocsf_obj.class_uid == 2001

    # Test normalization into STIX 2.1
    norm = TelemetryNormalizer.normalize_ocsf(ocsf_dict)
    assert norm.domain == TelemetryDomain.OCSF_SECURITY
    assert norm.severity == SeverityLevel.CRITICAL
    assert len(norm.raw_reference_hash) == 64
    assert any("ipv4:" in ioc for ioc in norm.iocs)


def test_cot_generation_and_normalization():
    sim = SiemSimulator(sector="Sector-4-North")
    cot_dict = sim.generate_cot_track(is_malicious=True)
    assert cot_dict["type"] == "a-h-G"
    assert "lat" in cot_dict and "lon" in cot_dict

    # Test Pydantic schema validation
    cot_obj = CoTTelemetry(**cot_dict)
    assert cot_obj.uid == cot_dict["uid"]

    # Test normalization into STIX 2.1
    norm = TelemetryNormalizer.normalize_cot(cot_dict)
    assert norm.domain == TelemetryDomain.TACTICAL_COT
    assert norm.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
    assert any("tactical-callsign:" in ioc for ioc in norm.iocs)
    assert len(norm.raw_reference_hash) == 64


def test_cot_xml_parsing():
    xml_cot = (
        '<event version="2.0" uid="SATELLITE-LEO-09" type="a-h-G" '
        'time="2026-09-15T12:00:00Z" start="2026-09-15T12:00:00Z" stale="2026-09-15T13:00:00Z" how="m-g">'
        '<point lat="45.1234" lon="12.5678" hae="540000" ce="10" le="10"/>'
        '<detail><status callsign="SATELLITE-LEO-09" readiness="compromised"/><jamming band="Ku-Band"/></detail>'
        '</event>'
    )
    norm = TelemetryNormalizer.normalize_cot(xml_cot)
    assert norm.original_alert_id == "SATELLITE-LEO-09"
    assert norm.domain == TelemetryDomain.TACTICAL_COT
    assert norm.severity == SeverityLevel.CRITICAL
    assert any("rf-band:KU-BAND" in ioc for ioc in norm.iocs)


def test_siem_batch_generation():
    sim = SiemSimulator(sector="Sector-4-North")
    batch = sim.generate_batch(count=30, scenario="apt_hybrid")
    assert len(batch) == 30

    normalized = TelemetryNormalizer.normalize_batch(batch)
    assert len(normalized) == 30
    domains = {n.domain for n in normalized}
    assert len(domains) >= 2  # Multi-domain verified


def test_xai_feature_attribution_calculation():
    sim = SiemSimulator(sector="Sector-4-North")
    batch = sim.generate_batch(count=20, scenario="apt_hybrid")
    normalized = TelemetryNormalizer.normalize_batch(batch)

    clusters = SpatioTemporalGraphEngine.correlate_alerts(normalized, sector="Sector-4-North")
    assert len(clusters) > 0

    for cluster in clusters:
        assert cluster.xai_explanation is not None
        assert isinstance(cluster.xai_explanation, XAiExplanation)
        assert cluster.xai_explanation.posterior_confidence >= 0.40
        attributions = cluster.xai_explanation.feature_attributions
        assert len(attributions) == 4
        # Weights should sum to 100% (within rounding margin)
        total_weight = sum(a.importance_weight for a in attributions)
        assert 99.0 <= total_weight <= 101.0
        assert any(a.feature_name == "Multi-Domain Cross-Sensor Fusion" for a in attributions)


def test_mcp_siem_simulation_service():
    service = AresDefenseMcpService()
    sim_res = service.simulate_siem(count=15, scenario="apt_hybrid", sector="Sector-4-North")
    assert sim_res["status"] == "SUCCESS"
    assert sim_res["new_alerts_ingested"] >= 15

    corr_res = service.correlate_alerts(sector="Sector-4-North")
    assert corr_res["status"] == "SUCCESS"
    assert corr_res["incident_clusters_identified"] >= 1
    assert "xai_explanation" in corr_res["clusters"][0]

    bluf_res = service.generate_bluf()
    assert "report_id" in bluf_res
    assert bluf_res["xai_explanation"] is not None


def test_api_simulate_endpoint():
    res = client.post("/api/simulate", json={
        "count": 10,
        "scenario": "apt_hybrid",
        "sector": "Sector-4-North"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["new_alerts_ingested"] >= 10


def test_api_ingest_ocsf_and_cot():
    sim = SiemSimulator(sector="Sector-4-North")
    ocsf_finding = sim.generate_ocsf_finding(is_malicious=True)
    cot_track = sim.generate_cot_track(is_malicious=True)

    res = client.post("/api/ingest", json=[ocsf_finding, cot_track])
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["new_alerts_ingested"] == 2
