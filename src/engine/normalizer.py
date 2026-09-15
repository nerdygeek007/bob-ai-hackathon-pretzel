"""
ARES Telemetry Normalizer
Converts heterogeneous raw logs (CEF, Syslog, EDR, Satellite Telemetry) into standard STIX 2.1 entities.
Extracts IOCs, computes SHA-256 provenance hashes, and assigns severity.
"""

import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any, Union
from src.engine.schemas import (
    RawTelemetryAlert,
    NormalizedStixEntity,
    SeverityLevel,
    TelemetryDomain,
    OCSFSecurityFinding,
    CoTTelemetry
)


class TelemetryNormalizer:
    """Normalizes raw heterogeneous alert streams (CEF, Syslog, EDR, OCSF, CoT) into standard STIX 2.1 objects."""

    @staticmethod
    def extract_iocs(text: str) -> List[str]:
        """Extracts IPs, domain names, hashes, CVEs, and defense asset tags from raw text."""
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

        # CVEs
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        for cve in re.findall(cve_pattern, text, re.IGNORECASE):
            iocs.add(f"cve:{cve.upper()}")

        # Process names
        proc_pattern = r'\b([a-zA-Z0-9_\-\.]+\.(?:exe|sh|bin|dll|ps1|bat))\b'
        for proc in re.findall(proc_pattern, text, re.IGNORECASE):
            iocs.add(f"process:{proc.lower()}")

        # Satellite / Defense asset tags
        asset_pattern = r'\b(SAT-[A-Z0-9-]+|PLC-[A-Z0-9-]+|GW-[0-9]+|S[0-9]-GW-[0-9]+|UAV-[A-Z0-9-]+)\b'
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
        if any(w in payload_lower for w in ["critical", "zero_day", "unauthorized modbus", "unauthorized_modbus", "unauthorized", "transponder lock lost", "rf jamming", "carrier jamming", "dirty pipe"]):
            return SeverityLevel.CRITICAL

        # High triggers
        if any(w in payload_lower for w in ["failed ssh logins", "auth_fail_burst", "auth_burst_fail", "privilege_escalation", "powershell.exe", "lsass", "c2 node", "cobalt strike", "beaconing", "ephemeris_anomaly", "ephemeris drift", "telemetry lock disrupted", "doppler"]):
            return SeverityLevel.HIGH

        # Medium triggers
        if any(w in payload_lower for w in ["port scan", "port_scan", "syn probe", "uncommon activity", "snr drop"]):
            return SeverityLevel.MEDIUM

        # Low triggers / benign
        is_truly_authorized = "authorized" in payload_lower and "unauthorized" not in payload_lower
        if is_truly_authorized or any(w in payload_lower for w in ["info:", "scheduled", "backup"]):
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
    def normalize_ocsf(cls, finding: Union[Dict[str, Any], OCSFSecurityFinding]) -> NormalizedStixEntity:
        """Converts an OCSF v1.1 Security Finding (Class 2001/1001) into a standard STIX 2.1 entity."""
        if isinstance(finding, OCSFSecurityFinding):
            data = finding.model_dump()
        elif isinstance(finding, dict):
            data = finding
        else:
            raise ValueError(f"Invalid OCSF finding format: {type(finding)}")

        raw_str = json.dumps(data, sort_keys=True)
        raw_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

        # Extract OCSF fields
        finding_info = data.get("finding_info", {})
        title = finding_info.get("title") or "OCSF Security Finding"
        finding_uid = finding_info.get("uid") or f"OCSF-{uuid.uuid4().hex[:8].upper()}"
        timestamp = data.get("time") or "2026-09-15T12:00:00Z"
        
        # Severity mapping: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
        sev_id = data.get("severity_id", 3)
        if sev_id >= 5:
            severity = SeverityLevel.CRITICAL
        elif sev_id == 4:
            severity = SeverityLevel.HIGH
        elif sev_id == 3:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        iocs = set(cls.extract_iocs(raw_str))

        # OCSF Observables list
        for obs in data.get("observables", []):
            obs_type = obs.get("type", "observable")
            obs_val = obs.get("value")
            if obs_val:
                iocs.add(f"{obs_type}:{obs_val}")

        device = data.get("device") or {}
        if device.get("ip"):
            iocs.add(f"ipv4:{device['ip']}")
        if device.get("hostname"):
            iocs.add(f"target:{device['hostname']}")

        confidence = 0.96 if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else 0.75

        return NormalizedStixEntity(
            stix_id=f"stix-obs-{finding_uid.lower()}",
            original_alert_id=finding_uid,
            timestamp=str(timestamp),
            domain=TelemetryDomain.OCSF_SECURITY,
            entity_type="observed-data",
            name=f"OCSF 2001 Finding [{title}]",
            description=f"{title}: {finding_info.get('desc', raw_str[:200])}",
            severity=severity,
            confidence=confidence,
            iocs=sorted(list(iocs)),
            tactics_hint=data.get("metadata", {}).get("event_code", "OCSF_FINDING"),
            raw_reference_hash=raw_hash
        )

    @classmethod
    def normalize_cot(cls, cot: Union[str, Dict[str, Any], CoTTelemetry]) -> NormalizedStixEntity:
        """Converts Cursor-on-Target (CoT) XML or JSON defense telemetry into a standard STIX 2.1 entity."""
        if isinstance(cot, CoTTelemetry):
            cot_dict = cot.model_dump()
            raw_str = json.dumps(cot_dict, sort_keys=True)
            uid = cot.uid
            cot_type = cot.type
            timestamp = cot.time
            lat, lon = cot.lat, cot.lon
            detail = cot.detail
        elif isinstance(cot, dict):
            cot_dict = cot
            raw_str = json.dumps(cot_dict, sort_keys=True)
            uid = cot_dict.get("uid", f"COT-{uuid.uuid4().hex[:6].upper()}")
            cot_type = cot_dict.get("type", "a-u-G")
            timestamp = cot_dict.get("time", "2026-09-15T12:00:00Z")
            lat = float(cot_dict.get("lat", 0.0))
            lon = float(cot_dict.get("lon", 0.0))
            detail = cot_dict.get("detail", {})
        elif isinstance(cot, str):
            raw_str = cot.strip()
            if raw_str.startswith("<"):
                # Parse XML CoT
                try:
                    root = ET.fromstring(raw_str)
                    uid = root.attrib.get("uid", f"COT-{uuid.uuid4().hex[:6].upper()}")
                    cot_type = root.attrib.get("type", "a-u-G")
                    timestamp = root.attrib.get("time", "2026-09-15T12:00:00Z")
                    pt = root.find("point")
                    lat = float(pt.attrib.get("lat", 0.0)) if pt is not None else 0.0
                    lon = float(pt.attrib.get("lon", 0.0)) if pt is not None else 0.0
                    detail = {}
                    detail_el = root.find("detail")
                    if detail_el is not None:
                        for child in detail_el:
                            detail[child.tag] = child.attrib
                except Exception:
                    uid = f"COT-{uuid.uuid4().hex[:6].upper()}"
                    cot_type = "a-u-G"
                    timestamp = "2026-09-15T12:00:00Z"
                    lat, lon = 0.0, 0.0
                    detail = {}
            else:
                cot_json = json.loads(raw_str)
                return cls.normalize_cot(cot_json)
        else:
            raise ValueError(f"Unsupported CoT format: {type(cot)}")

        raw_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

        # Severity determined by MIL-STD-2525 type:
        # a-h = hostile, a-f = friendly, a-u = unknown, a-n = neutral
        is_hostile = cot_type.startswith("a-h") or "hostile" in str(detail).lower() or "jamming" in str(detail).lower()
        is_compromised = "compromised" in str(detail).lower() or "breach" in str(detail).lower()

        if is_hostile and is_compromised:
            severity = SeverityLevel.CRITICAL
        elif is_hostile:
            severity = SeverityLevel.HIGH
        elif cot_type.startswith("a-u"):
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        iocs = set(cls.extract_iocs(raw_str))
        iocs.add(f"tactical-callsign:{uid}")
        iocs.add(f"cot-type:{cot_type}")
        if lat != 0.0 or lon != 0.0:
            iocs.add(f"geo-pos:{round(lat, 4)},{round(lon, 4)}")

        confidence = 0.98 if is_hostile else 0.80

        return NormalizedStixEntity(
            stix_id=f"stix-obs-{uid.lower()}",
            original_alert_id=uid,
            timestamp=str(timestamp),
            domain=TelemetryDomain.TACTICAL_COT,
            entity_type="observed-data",
            name=f"CoT Tactical Track [{uid}]",
            description=f"MIL-STD-2525 Track {uid} (Type: {cot_type}, Pos: {lat:.2f},{lon:.2f}). Detail: {str(detail)[:150]}",
            severity=severity,
            confidence=confidence,
            iocs=sorted(list(iocs)),
            tactics_hint=cot_type,
            raw_reference_hash=raw_hash
        )

    @classmethod
    def normalize_batch(cls, alerts: List[Union[RawTelemetryAlert, OCSFSecurityFinding, CoTTelemetry, Dict[str, Any]]]) -> List[NormalizedStixEntity]:
        """Batch normalizes an incoming list of raw alerts, OCSF findings, or CoT tracks."""
        normalized: List[NormalizedStixEntity] = []
        for a in alerts:
            if isinstance(a, NormalizedStixEntity):
                normalized.append(a)
            elif isinstance(a, RawTelemetryAlert):
                normalized.append(cls.normalize_alert(a))
            elif isinstance(a, OCSFSecurityFinding):
                normalized.append(cls.normalize_ocsf(a))
            elif isinstance(a, CoTTelemetry):
                normalized.append(cls.normalize_cot(a))
            elif isinstance(a, dict):
                if "class_uid" in a or "finding_info" in a:
                    normalized.append(cls.normalize_ocsf(a))
                elif "lat" in a and ("lon" in a or "uid" in a):
                    normalized.append(cls.normalize_cot(a))
                elif "raw_payload" in a:
                    normalized.append(cls.normalize_alert(RawTelemetryAlert(**a)))
                else:
                    # Generic alert dict
                    normalized.append(cls.normalize_alert(RawTelemetryAlert(
                        alert_id=a.get("alert_id", str(uuid.uuid4())),
                        timestamp=a.get("timestamp", "2026-09-15T12:00:00Z"),
                        domain=TelemetryDomain(a.get("domain", "cyber_siem")),
                        source_name=a.get("source_name", "generic_siem"),
                        raw_payload=json.dumps(a)
                    )))
            elif isinstance(a, str):
                if a.strip().startswith("<event"):
                    normalized.append(cls.normalize_cot(a))
                else:
                    try:
                        parsed = json.loads(a)
                        normalized.extend(cls.normalize_batch([parsed]))
                    except Exception:
                        pass
        return normalized
