// ============================================================
// SENTINEL-X Type System
// Core domain types for the threat intelligence platform
// ============================================================

export type DomainType = 'SIEM' | 'SATELLITE_SPACE' | 'SENSORS';
export type SourceType =
  | 'mordor'
  | 'evtx'
  | 'cic_ids'
  | 'et_open'
  | 'nasa_telemanom'
  | 'esa_opssat'
  | 'opensky'
  | 'network_sensor'
  | 'endpoint_sensor'
  | 'facility_sensor';

export type EnrichmentSourceType = 'mitre_attack' | 'cisa_kev';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'UNKNOWN';
export type PriorityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
export type CorrelationStatus = 'CORRELATED' | 'STANDALONE' | 'PENDING';
export type SourceStatus = 'OPERATIONAL' | 'DEGRADED' | 'ERROR' | 'DISABLED';
export type ThreatAssessment = 'LIKELY_THREAT' | 'LIKELY_FALSE_POSITIVE' | 'REQUIRES_INVESTIGATION';

// ============================================================
// Data Sources
// ============================================================

export interface SubSource {
  id: string;
  name: string;
  sourceType: SourceType;
  domain: DomainType;
  enabled: boolean;
  status: SourceStatus;
  description: string;
  lastIngestion: string | null;
  recordsProcessed: number;
  eventsPerMinute: number;
  latencyMs: number;
  errorCount: number;
  connectionHost?: string;
  connectionPort?: number;
  protocol?: string;
  version?: string;
}

export interface PrimaryDomain {
  id: DomainType;
  label: string;
  subtitle: string;
  enabled: boolean;
  status: SourceStatus;
  sources: SubSource[];
  totalRecords: number;
}

export interface EnrichmentSource {
  id: EnrichmentSourceType;
  label: string;
  enabled: boolean;
  status: SourceStatus;
  lastSync: string;
  totalEntries: number;
  description: string;
}

// ============================================================
// Alerts (Live alert records — sparse)
// ============================================================

export interface Alert {
  alertId: string;
  timestamp: string;
  domain: DomainType;
  sourceId: SourceType;
  sourceName: string;

  // Sparse fields — may be null/undefined
  asset?: string;
  indicator?: string;
  eventType?: string;
  title?: string;
  attackBehavior?: string;
  sourceSeverity?: SeverityLevel;
  priority?: PriorityLevel; // Sentinel-X computed priority
  confidence?: number; // 0–100 (detection confidence)
  correlationConfidence?: number; // 0–100
  behavioralMatch?: string;
  mitreId?: string;
  mitreName?: string;
  mitreTactic?: string;
  mitreDescription?: string;
  whatHappened?: string;
  whyPrioritized?: string[];
  priorityReason?: string;
  recommendedAction?: string;
  status?: 'New' | 'Investigating' | 'Resolved' | 'False Positive' | 'Confirmed Threat';
  evidenceTimeline?: { time: string; event: string; source: string; detail: string }[];
  telemetryDetail?: {
    parameter: string;
    observed: number;
    expected: number;
    deviation: string;
    isAnomaly: boolean;
  };
  correlationStatus: CorrelationStatus;
  relatedIncidentId?: string;

  // Raw reference (not embedded inline)
  rawReference: string;
}

// ============================================================
// Normalized Events
// ============================================================

export interface NormalizedEvent {
  eventId: string;
  timestamp: string;
  source: SourceType;
  sourceName: string;
  sourceType: DomainType;

  // All optional — sparse canonical model
  asset?: string;
  indicators?: string[];
  eventType?: string;
  description?: string;
  sourceSeverity?: SeverityLevel;
  confidence?: number;

  // Enrichment
  mitreIds?: string[];
  cveIds?: string[];

  // Provenance
  rawReference: string;
  dataCompleteness: number; // 0–100 %

  // Field presence map (for normalization display)
  fieldPresence: Record<string, boolean>;
}

// ============================================================
// Incidents (Correlated)
// ============================================================

export interface CorroborationEvidence {
  sameAsset: boolean;
  sameIndicator: boolean;
  temporalProximity: boolean;
  multipleIndependentSources: boolean;
  similarBehavior: boolean;
  threatIntelMatch: boolean;
  cisaKevMatch: boolean;
}

export interface Incident {
  incidentId: string;
  title?: string;
  priority: PriorityLevel;
  riskScore: number; // 0–100
  confidence: number; // 0–100
  dataCompleteness: number; // 0–100

  affectedAsset: string;
  affectedAssets?: string[];
  evidenceDomains: DomainType[];
  correlatedAlertIds: string[];
  mitreIds: string[];
  cveIds: string[];

  status: IncidentStatus;
  firstSeen: string;
  lastSeen: string;

  threatAssessment: ThreatAssessment;
  threatAssessmentReasons: string[];

  corroboration: CorroborationEvidence;
  riskFactors: RiskFactors;

  // SENTINEL-X computed — NOT raw source severity
  sentinelPriority: PriorityLevel;
  sourceSeverities: { source: string; severity: SeverityLevel | null }[];

  blufSummary?: string;
  timeline?: {
    time: string;
    stage: string;
    description: string;
    source: string;
    mitre?: string;
  }[];
}

// ============================================================
// Risk Scoring
// ============================================================

export interface RiskFactors {
  evidenceStrength: number; // 0–100
  assetCriticality: number; // 0–100
  correlationStrength: number; // 0–100
  threatIntelConfidence: number; // 0–100
  temporalCorrelation: number; // 0–100
}

export interface RiskWeights {
  evidenceStrength: number; // fraction, sum = 1.0
  assetCriticality: number;
  correlationStrength: number;
  threatIntelConfidence: number;
  temporalCorrelation: number;
}

export interface RiskScore {
  incidentId: string;
  finalScore: number;
  factors: RiskFactors;
  weights: RiskWeights;
  explanation: string;
}

// ============================================================
// MITRE ATT&CK
// ============================================================

/**
 * Result returned by the RAG backend (POST /api/mitre/map).
 * Mirrors the Python Pydantic MitreMappingResult schema.
 */
export interface MitreMappingResult {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence_score: number; // 0–100
  evidence: string[];
}

export interface MitreTechnique {
  techniqueId: string;
  techniqueName: string;
  subTechniqueName?: string;
  tactic: string;
  description: string;
  confidence: number;
  evidenceSources: string[];
  relatedAlertIds: string[];
  relatedIncidentIds: string[];
  threatActors?: string[];
  platforms?: string[];
}

// ============================================================
// Threat Indicators
// ============================================================

export type IndicatorType = 'IP' | 'DOMAIN' | 'HASH' | 'CVE' | 'ACTOR' | 'CAMPAIGN' | 'URL';

export interface ThreatIndicator {
  indicatorId: string;
  value: string;
  type: IndicatorType;
  source: string;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  relatedIncidentIds: string[];
  tags: string[];
  cisaKev?: CISAKEVEntry;
}

export interface CISAKEVEntry {
  cveId: string;
  vendor: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaign: boolean;
  relatedAssets: string[];
  relatedIncidentIds: string[];
}

// ============================================================
// Telemetry
// ============================================================

export interface TelemetryRecord {
  recordId: string;
  timestamp: string;
  sourceId: SourceType;
  sourceName: string;

  // Sparse
  spacecraftId?: string;
  aircraftId?: string;
  sensorId?: string;
  telemetryParameter?: string;
  observedValue?: number;
  expectedValue?: number;
  deviation?: number;
  anomalyScore?: number; // 0–100
  location?: string;
  operationalStatus?: string;
  signalInfo?: string;

  isAnomaly: boolean;
  anomalyClassification: 'TELEMETRY_ANOMALY' | 'NORMAL' | 'UNKNOWN';
  // IMPORTANT: Telemetry anomaly ≠ cyber attack without corroboration
  corroboratedByCyberEvidence: boolean;
}

// ============================================================
// Normalization Pipeline
// ============================================================

export interface NormalizationField {
  sourceField: string;
  canonicalField: string;
  present: boolean;
  value?: string;
}

export interface NormalizationRecord {
  sourceId: SourceType;
  sourceName: string;
  domain: DomainType;
  rawSample: Record<string, string>;
  fields: NormalizationField[];
  dataCompleteness: number;
  adapterName: string;
}

// ============================================================
// Correlation
// ============================================================

export interface CorrelationRule {
  ruleId: string;
  label: string;
  description: string;
  enabled: boolean;
  configurable?: boolean;
}

export interface CorrelationConfig {
  windowMinutes: number;
  minCorroboratingSources: number;
  rules: CorrelationRule[];
}

// ============================================================
// BLUF Report
// ============================================================

export interface BLUFReport {
  reportId: string;
  incidentId: string;
  generatedAt: string;
  priority: PriorityLevel;
  bottomLine: string;
  whyItMatters: string;
  evidenceSummary: string[];
  mitreIds: string[];
  riskScore: number;
  confidence: number;
  recommendedActions: string[];
  classificationNote: string;
}

// ============================================================
// System Health
// ============================================================

export interface SourceHealthMetric {
  sourceId: SourceType | EnrichmentSourceType;
  sourceName: string;
  domain: DomainType | 'ENRICHMENT';
  connectionStatus: 'CONNECTED' | 'DISCONNECTED' | 'DEGRADED' | 'DISABLED';
  latencyMs: number | null;
  recordsProcessed: number;
  eventsPerMinute: number;
  lastIngestion: string | null;
  errorCount: number;
  enabled: boolean;
}

// ============================================================
// Simulation & Scenarios
// ============================================================

export type AttackScenario =
  | 'normal'
  | 'brute_force'
  | 'powershell'
  | 'multi_stage'
  | 'false_positive'
  | 'satellite_anomaly';

export interface SimEvent {
  id: string;
  event_id: string;
  timestamp: string;
  source: string;
  eventType: string;
  event_type: string;
  asset: string;
  severity: SeverityLevel;
  mitre?: string;
  mitre_technique?: string;
  detection_confidence?: number;
  alert_id?: string;
  incident_id?: string;
  raw_event: Record<string, unknown>;
  normalized_event: Record<string, unknown>;
  pipeline_stage?: string;
  correlation_note?: string;
  user?: string;
  commandLine?: string;
  scenario?: AttackScenario;
}
