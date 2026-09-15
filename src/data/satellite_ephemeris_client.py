"""
ARES Satellite Ephemeris Client
Fetches real-world orbital ephemeris from CelesTrak NORAD General Perturbations (GP) open feeds,
performs orbital mechanics computations (altitude, period, orbit regime),
and generates physics-grounded satellite electronic warfare (EW) anomaly alerts.
Includes automatic offline fallback to local cached catalog for air-gapped resilience.
"""

import os
import json
import math
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from src.engine.schemas import (
    SatelliteEphemeris,
    RawTelemetryAlert,
    TelemetryDomain,
    SeverityLevel
)

# Standard Earth gravitational parameter and WGS84 radius
MU_EARTH_KM3_S2 = 398600.4418  # km^3 / s^2
WGS84_EARTH_RADIUS_KM = 6378.137  # km

CELESTRAK_BASE_URL = "https://celestrak.org/NORAD/elements/gp.php"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "cached_satellite_ephemeris.json")


class SatelliteEphemerisClient:
    """Client for authoritative CelesTrak / NORAD Satellite Ephemeris Data."""

    def __init__(self, timeout_seconds: float = 3.0, cache_path: str = CACHE_PATH):
        self.timeout = timeout_seconds
        self.cache_path = cache_path

    def fetch_raw_catalog(self, group: str = "military", force_live: bool = False) -> List[Dict[str, Any]]:
        """
        Fetches satellite GP records from CelesTrak, falling back to local cache if offline.
        """
        if not force_live and os.path.exists(self.cache_path):
            # Try live first with short timeout, fall back immediately if unreachable
            try:
                return self._fetch_live(group)
            except Exception:
                return self._load_cache()

        if force_live:
            return self._fetch_live(group)

        return self._load_cache()

    def _fetch_live(self, group: str) -> List[Dict[str, Any]]:
        url = f"{CELESTRAK_BASE_URL}?GROUP={group}&FORMAT=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ARES-Defense-Intel-Core/1.0 (Defense Research)"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, list) and len(data) > 0:
                return data
            raise ValueError("Empty response from CelesTrak API")

    def _load_cache(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.cache_path):
            return []
        with open(self.cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def compute_orbital_parameters(record: Dict[str, Any]) -> SatelliteEphemeris:
        """
        Computes orbital altitude, period, and regime from NORAD GP elements.
        """
        norad_id = int(record.get("NORAD_CAT_ID", 0))
        name = str(record.get("OBJECT_NAME", "UNKNOWN_SAT")).strip()
        obj_id = str(record.get("OBJECT_ID", "UNKNOWN_ID")).strip()
        epoch = str(record.get("EPOCH", datetime.now(timezone.utc).isoformat()))
        inc = float(record.get("INCLINATION", 0.0))
        ecc = float(record.get("ECCENTRICITY", 0.0))
        mean_motion = float(record.get("MEAN_MOTION", 1.0))

        # Mean motion n in rad/s: n_rad = n * 2*pi / 86400
        if mean_motion > 0:
            n_rad = mean_motion * (2.0 * math.pi) / 86400.0
            # Semi-major axis a = (mu / n^2)^(1/3)
            semi_major_axis_km = (MU_EARTH_KM3_S2 / (n_rad ** 2)) ** (1.0 / 3.0)
            # Perigee altitude = a * (1 - e) - R_earth
            altitude_km = round(semi_major_axis_km * (1.0 - ecc) - WGS84_EARTH_RADIUS_KM, 1)
            period_minutes = round(1440.0 / mean_motion, 2)
        else:
            altitude_km = 0.0
            period_minutes = 0.0

        # Classify orbital regime
        if altitude_km < 2000.0:
            orbit_type = "LEO"
        elif 2000.0 <= altitude_km < 35000.0:
            orbit_type = "MEO"
        elif 35000.0 <= altitude_km <= 36500.0 and ecc < 0.05:
            orbit_type = "GEO"
        else:
            orbit_type = "HEO"

        return SatelliteEphemeris(
            norad_cat_id=norad_id,
            object_name=name,
            object_id=obj_id,
            epoch=epoch,
            inclination_deg=inc,
            eccentricity=ecc,
            mean_motion=mean_motion,
            ra_of_asc_node=float(record.get("RA_OF_ASC_NODE", 0.0)),
            arg_of_pericenter=float(record.get("ARG_OF_PERICENTER", 0.0)),
            mean_anomaly=float(record.get("MEAN_ANOMALY", 0.0)),
            bstar=float(record.get("BSTAR", 0.0)) if record.get("BSTAR") is not None else None,
            altitude_km=altitude_km,
            period_minutes=period_minutes,
            orbit_type=orbit_type,
            source="CelesTrak NORAD Open Catalog"
        )

    def get_catalog(self, query: Optional[str] = None) -> List[SatelliteEphemeris]:
        """Returns parsed SatelliteEphemeris models matching an optional query filter."""
        raw_list = self.fetch_raw_catalog()
        catalog = []
        for r in raw_list:
            sat = self.compute_orbital_parameters(r)
            if query:
                q_upper = query.upper()
                if (q_upper in sat.object_name.upper() or 
                    q_upper in str(sat.norad_cat_id) or 
                    q_upper in sat.orbit_type.upper()):
                    catalog.append(sat)
            else:
                catalog.append(sat)
        return catalog

    def generate_satellite_anomaly_alerts(
        self,
        sector: str = "Sector-Space-LEO",
        satellite_query: Optional[str] = "SAR-LUPE"
    ) -> List[RawTelemetryAlert]:
        """
        Generates realistic multi-domain threat telemetry anchored to a real tracked satellite.
        Simulates:
        1. Satellite Uplink Jamming on real military bird (e.g. SAR-LUPE 2 NORAD:31797)
        2. Ephemeris orbit cross-check tracking anomaly
        3. Correlated Ground Station EDR credential abuse attempt
        4. SCADA Dish Tracking Controller Modbus azimuth slewing override
        """
        catalog = self.get_catalog(query=satellite_query)
        target_sat = catalog[0] if catalog else self.compute_orbital_parameters({
            "OBJECT_NAME": "SAR-LUPE 2",
            "OBJECT_ID": "2007-030A",
            "EPOCH": "2026-09-14T22:00:50.364576",
            "MEAN_MOTION": 15.62210974,
            "ECCENTRICITY": 0.00043247,
            "INCLINATION": 98.1102,
            "NORAD_CAT_ID": 31797
        })

        now = datetime.now(timezone.utc)
        alerts: List[RawTelemetryAlert] = []

        # 1. Real Satellite RF Carrier Jamming
        alerts.append(RawTelemetryAlert(
            alert_id=f"SAT-RF-{uuid.uuid4().hex[:8].upper()}",
            timestamp=(now - timedelta(minutes=14)).isoformat(),
            domain=TelemetryDomain.SATELLITE_EW,
            source_name=f"SAT-RELAY-NORAD-{target_sat.norad_cat_id}",
            raw_payload=(
                f"ANOMALY: High-power RF carrier jamming detected against {target_sat.object_name} "
                f"(NORAD:{target_sat.norad_cat_id}, Epoch {target_sat.epoch[:19]}, Orbit: {target_sat.orbit_type} "
                f"Alt: {target_sat.altitude_km}km, Inc: {target_sat.inclination_deg}°). "
                f"Ku-Band uplink carrier frequency 14.24 GHz experienced SNR degradation of 19.8 dB. "
                f"Telemetry lock disrupted over pass corridor."
            ),
            sector=sector,
            target_entity=f"{target_sat.object_name} (NORAD:{target_sat.norad_cat_id})",
            event_code="SAT_RF_JAM_NORAD",
            metadata={
                "norad_cat_id": target_sat.norad_cat_id,
                "satellite_name": target_sat.object_name,
                "altitude_km": target_sat.altitude_km,
                "orbit_type": target_sat.orbit_type,
                "inclination_deg": target_sat.inclination_deg,
                "period_minutes": target_sat.period_minutes,
                "snr_drop_db": 19.8,
                "carrier_frequency": "14.24 GHz",
                "ephemeris_source": target_sat.source
            }
        ))

        # 2. Ephemeris Orbit Propagation Anomaly (Spoofing / Ranging Drift)
        alerts.append(RawTelemetryAlert(
            alert_id=f"SAT-EPH-{uuid.uuid4().hex[:8].upper()}",
            timestamp=(now - timedelta(minutes=10)).isoformat(),
            domain=TelemetryDomain.SATELLITE_EW,
            source_name=f"TRACKING-STATION-RADAR",
            raw_payload=(
                f"EPHEMERIS_ANOMALY: Ranging telemetry mismatch for {target_sat.object_name} [NORAD:{target_sat.norad_cat_id}]. "
                f"Calculated Doppler velocity varies from CelesTrak GP propagation table by +142 m/s. "
                f"Suspected GPS/ephemeris spoofing or unannounced orbital maneuvering thruster pulse."
            ),
            sector=sector,
            target_entity=f"{target_sat.object_name}",
            event_code="SAT_EPHEMERIS_DRIFT",
            metadata={
                "norad_cat_id": target_sat.norad_cat_id,
                "doppler_delta_m_s": 142.0,
                "propagation_model": "SGP4/SDP4",
                "mean_motion": target_sat.mean_motion
            }
        ))

        # 3. Ground Station Cyber Intrusion (EDR)
        alerts.append(RawTelemetryAlert(
            alert_id=f"EDR-{uuid.uuid4().hex[:8].upper()}",
            timestamp=(now - timedelta(minutes=6)).isoformat(),
            domain=TelemetryDomain.CYBER_EDR,
            source_name="Ground-Station-EDR",
            raw_payload=(
                f"PROCESS_TAMPERING: powershell.exe injected into sat_tracking_daemon.exe on S4-GW-01. "
                f"Adversary modified antenna tracking ephemeris feed targeting NORAD:{target_sat.norad_cat_id}. "
                f"Outbound TLS connection to 203.0.113.88:443 detected."
            ),
            sector=sector,
            target_entity=f"S4-GW-01 (Ground-Station-Controller)",
            source_ip="10.4.1.1",
            destination_ip="203.0.113.88",
            event_code="EDR_PROCESS_SUSPICIOUS",
            metadata={"target_norad_id": target_sat.norad_cat_id, "process": "sat_tracking_daemon.exe"}
        ))

        # 4. SCADA Antenna Azimuth Slewing Hijack
        alerts.append(RawTelemetryAlert(
            alert_id=f"ICS-{uuid.uuid4().hex[:8].upper()}",
            timestamp=(now - timedelta(minutes=2)).isoformat(),
            domain=TelemetryDomain.SATELLITE_EW,
            source_name="SCADA-ANTENNA-PLC",
            raw_payload=(
                f"CRITICAL: Unauthorized Modbus/TCP command sent to Tracking Dish Motor Drive. "
                f"Azimuth forced 50 degrees away from {target_sat.object_name} pass coordinates, "
                f"inducing full satellite link black-out."
            ),
            sector=sector,
            target_entity="PLC-AZ-MOTOR-01",
            source_ip="10.4.1.1",
            event_code="ICS_MODBUS_UNAUTHORIZED_WRITE",
            metadata={"commanded_azimuth_offset_deg": 50.0, "targeted_satellite": target_sat.object_name}
        ))

        return alerts
