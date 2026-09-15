"""
ARES Defense Intelligence Core Schemas
Standardized data structures for Multi-Domain Telemetry, STIX 2.1 Normalization,
Incident Clusters, MITRE ATT&CK Mapping, and Military BLUF Briefings.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class TelemetryDomain(str, Enum):
    CYBER_SIEM = "cyber_siem"
    CYBER_EDR = "cyber_edr"
    SATELLITE_EW = "satellite_ew"
    KINETIC_RADAR = "kinetic_radar"
    OSINT_INTEL = "osint_intel"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RawTelemetryAlert(BaseModel):
    """Raw incoming alert from any sensor or telemetry stream."""
    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    domain: TelemetryDomain = Field(..., description="Originating domain")
    source_name: str = Field(..., description="Sensor or system name (e.g. QRadar, EDR-CrowdStrike, SAT-OPS-01)")
    raw_payload: str = Field(..., description="Unstructured or semi-structured raw log message")
    sector: Optional[str] = Field("Sector-Global", description="Operational sector or military base ID")
    target_entity: Optional[str] = Field(None, description="IP, hostname, transponder ID, or asset name")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_code: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NormalizedStixEntity(BaseModel):
    """Normalized STIX 2.1 compatible entity extracted from raw telemetry."""
    stix_id: str
    original_alert_id: str
    timestamp: str
    domain: TelemetryDomain
    entity_type: str = Field(..., description="e.g. indicator, observed-data, attack-pattern, identity")
    name: str
    description: str
    severity: SeverityLevel
    confidence: float = Field(0.85, ge=0.0, le=1.0)
    iocs: List[str] = Field(default_factory=list, description="Extracted IOCs (IPs, hashes, domain names, transponders)")
    tactics_hint: Optional[str] = None
    raw_reference_hash: str = Field(..., description="SHA-256 hash of raw payload for provenance tracking")


class MitreTechniqueMatch(BaseModel):
    """Matched MITRE ATT&CK technique with confidence and evidence."""
    technique_id: str = Field(..., description="e.g. T1059.001, T1078")
    name: str = Field(..., description="e.g. PowerShell, Valid Accounts")
    tactic: str = Field(..., description="e.g. Execution, Initial Access")
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_keywords: List[str] = Field(default_factory=list)
    evidence_alert_ids: List[str] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)


class CourseOfAction(BaseModel):
    """Wargamed defensive action option for commanders."""
    option_id: str = Field(..., description="e.g. COA-1, COA-2")
    title: str = Field(..., description="e.g. Targeted Quarantine & C2 Blackhole")
    action_type: str = Field(..., description="e.g. ISOLATE, REROUTE, RECONFIGURE, DECEIVE")
    containment_efficacy: float = Field(..., ge=0.0, le=1.0, description="Estimated containment %")
    mission_disruption_impact: str = Field(..., description="NONE, LOW, MEDIUM, HIGH")
    execution_time_seconds: int = Field(..., description="Estimated time to execute")
    tradeoff_summary: str = Field(..., description="Pros vs Cons explanation")
    is_recommended: bool = False


class IncidentCluster(BaseModel):
    """A correlated multi-domain incident comprising multiple alerts."""
    cluster_id: str = Field(..., description="e.g. INC-2026-ALPHA-01")
    created_at: str
    sector: str
    primary_threat_actor: Optional[str] = "Unknown APT"
    attribution_confidence: float = 0.75
    overall_severity: SeverityLevel
    bayesian_threat_confidence: float = Field(0.90, ge=0.0, le=1.0)
    is_adversarial_chaff: bool = False
    chaff_entropy_score: float = 0.0
    alert_count: int
    domains_involved: List[TelemetryDomain]
    alerts: List[NormalizedStixEntity]
    mitre_techniques: List[MitreTechniqueMatch] = Field(default_factory=list)
    attack_lifecycle_stage: str = Field("Active Intrusion", description="Reconnaissance, Initial Access, Lateral Movement, Impact")


class ProvenanceCitation(BaseModel):
    """Cryptographic evidence link for every statement in the BLUF."""
    claim_index: int
    claim_text: str
    source_alert_id: str
    source_sensor: str
    source_timestamp: str
    sha256_hash: str
    verification_status: str = "VERIFIED_GROUNDED"


class CommanderBlufReport(BaseModel):
    """Military-Standard BLUF Investigation Briefing."""
    report_id: str
    cluster_id: str
    generated_at: str
    classification_level: str = "SECRET // NOFORN // EXERCISE"
    sector: str
    
    # 1. BLUF
    bottom_line_up_front: str = Field(..., description="1-2 concise executive sentences")
    severity: SeverityLevel
    bayesian_confidence: float
    threat_actor_attribution: str
    
    # 2. Key Findings
    key_findings: List[str]
    provenance_citations: List[ProvenanceCitation]
    
    # 3. MITRE TTPs
    mitre_ttps: List[MitreTechniqueMatch]
    
    # 4. Wargamed COAs
    wargamed_coas: List[CourseOfAction]
    
    # 5. watsonx Granite Guardian Assurance
    guardian_grounding_score: float = Field(0.98, description="0-1 score verifying zero hallucinations")
    guardian_verdict: str = "PASSED_DEFENSE_GROUNDING"
