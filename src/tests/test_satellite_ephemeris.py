"""
ARES Defense Intelligence - Satellite Ephemeris Integration Test Suite
Validates:
1. Offline fallback cache & CelesTrak GP catalog structure
2. Orbital mechanics calculation (altitude, period, orbit regime)
3. Physics-grounded satellite EW anomaly alert generation
4. STIX 2.1 normalization and NORAD/RF IOC extraction
5. REST API /api/satellites/ephemeris and real_ephemeris ingestion
"""

import pytest
from fastapi.testclient import TestClient

from src.data.satellite_ephemeris_client import SatelliteEphemerisClient
from src.engine.schemas import TelemetryDomain, SeverityLevel
from src.engine.normalizer import TelemetryNormalizer
from src.api import app


@pytest.fixture
def ephemeris_client():
    return SatelliteEphemerisClient()


@pytest.fixture
def api_client():
    return TestClient(app)


def test_ephemeris_client_offline_cache(ephemeris_client):
    """Asserts that client can load satellite catalog from offline cache."""
    catalog = ephemeris_client.get_catalog()
    assert len(catalog) >= 10, f"Expected at least 10 cached satellites, found {len(catalog)}"
    
    first = catalog[0]
    assert first.norad_cat_id > 0
    assert first.object_name
    assert first.epoch
    assert first.mean_motion > 0
    assert first.orbit_type in ["LEO", "MEO", "GEO", "HEO"]


def test_orbital_parameter_calculations(ephemeris_client):
    """Verifies altitude, orbital period, and orbit classification math."""
    # Test LEO Satellite (SAR-LUPE 2: mean motion ~ 15.6 rev/day)
    sar_lupe_raw = {
        "NORAD_CAT_ID": 31797,
        "OBJECT_NAME": "SAR-LUPE 2",
        "OBJECT_ID": "2007-030A",
        "EPOCH": "2026-09-14T22:00:50.364576",
        "MEAN_MOTION": 15.62210974,
        "ECCENTRICITY": 0.00043247,
        "INCLINATION": 98.1102
    }
    sar_lupe = ephemeris_client.compute_orbital_parameters(sar_lupe_raw)
    assert sar_lupe.orbit_type == "LEO"
    assert 300.0 <= sar_lupe.altitude_km <= 600.0, f"Unexpected altitude {sar_lupe.altitude_km}"
    assert 90.0 <= sar_lupe.period_minutes <= 100.0, f"Unexpected period {sar_lupe.period_minutes}"

    # Test MEO Satellite (GPS NAVSTAR: mean motion ~ 2.0 rev/day)
    gps_raw = {
        "NORAD_CAT_ID": 24876,
        "OBJECT_NAME": "NAVSTAR 43 (USA 132)",
        "OBJECT_ID": "1997-035A",
        "EPOCH": "2026-09-14T18:00:00.000000",
        "MEAN_MOTION": 2.0055,
        "ECCENTRICITY": 0.005,
        "INCLINATION": 55.0
    }
    gps = ephemeris_client.compute_orbital_parameters(gps_raw)
    assert gps.orbit_type == "MEO"
    assert 19000.0 <= gps.altitude_km <= 21000.0, f"Unexpected GPS altitude {gps.altitude_km}"
    assert 700.0 <= gps.period_minutes <= 730.0, f"Unexpected GPS period {gps.period_minutes}"


def test_satellite_anomaly_alert_generation(ephemeris_client):
    """Asserts that generated alerts anchor to real tracked satellite telemetry."""
    alerts = ephemeris_client.generate_satellite_anomaly_alerts(
        sector="Sector-Space-LEO",
        satellite_query="SAR-LUPE"
    )
    assert len(alerts) == 4
    
    # Check RF Jamming Alert
    rf_alert = alerts[0]
    assert rf_alert.domain == TelemetryDomain.SATELLITE_EW
    assert "NORAD" in rf_alert.raw_payload
    assert "SAR-LUPE" in rf_alert.target_entity
    assert rf_alert.metadata.get("norad_cat_id") == 31797
    assert rf_alert.metadata.get("orbit_type") == "LEO"
    assert rf_alert.metadata.get("snr_drop_db") == 19.8


def test_stix_normalization_of_ephemeris_alerts(ephemeris_client):
    """Asserts STIX 2.1 normalizer extracts satellite IOCs and computes cryptographic hashes."""
    alerts = ephemeris_client.generate_satellite_anomaly_alerts(sector="Sector-Space-LEO")
    normalized = TelemetryNormalizer.normalize_batch(alerts)
    
    assert len(normalized) == len(alerts)
    for n in normalized:
        assert n.stix_id.startswith("stix-obs-")
        assert len(n.raw_reference_hash) == 64  # SHA-256 length
        assert n.confidence >= 0.70

    first_iocs = normalized[0].iocs
    # Check for extracted satellite and RF IOCs
    assert any("norad-cat-id:" in ioc for ioc in first_iocs)
    assert any("defense-satellite-asset:" in ioc for ioc in first_iocs)
    assert any("rf-band:" in ioc for ioc in first_iocs)
    assert normalized[0].severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]


def test_api_satellite_endpoints(api_client):
    """Verifies REST API endpoints for ephemeris retrieval and ingestion."""
    # Test GET /api/satellites/ephemeris
    res = api_client.get("/api/satellites/ephemeris")
    assert res.status_code == 200
    body = res.json()
    assert body["count"] >= 10
    assert "satellites" in body
    assert body["satellites"][0]["norad_cat_id"] > 0

    # Test GET /api/satellites/ephemeris with query
    res_query = api_client.get("/api/satellites/ephemeris?query=SAR-LUPE")
    assert res_query.status_code == 200
    assert res_query.json()["count"] >= 1
    assert "SAR-LUPE" in res_query.json()["satellites"][0]["object_name"]

    # Test POST /api/ingest with real_ephemeris scenario
    res_ingest = api_client.post("/api/ingest", json={
        "scenario": "real_ephemeris",
        "sector": "Sector-Space-LEO",
        "clear_session": True
    })
    assert res_ingest.status_code == 200
    ingest_data = res_ingest.json()
    assert ingest_data["status"] == "SUCCESS"
    assert ingest_data["new_alerts_ingested"] == 4
    assert ingest_data["sector"] == "Sector-Space-LEO"
