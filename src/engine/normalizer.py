"""
ARES Telemetry Normalizer
Converts heterogeneous raw logs (CEF, Syslog, EDR, Satellite Telemetry) into standard STIX 2.1 entities.
Extracts IOCs, computes SHA-256 provenance hashes, and assigns severity.
"""

import hashlib
import re
from typing import List, Optional
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
