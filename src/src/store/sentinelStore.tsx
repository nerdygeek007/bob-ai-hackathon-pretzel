import React, { createContext, useContext, useState, useMemo, useEffect, useRef, ReactNode } from 'react';
import {
  PrimaryDomain,
  EnrichmentSource,
  Alert,
  Incident,
  CorrelationConfig,
  DomainType,
  EnrichmentSourceType,
  RiskWeights,
  AttackScenario,
  SimEvent,
} from '../types';
import { initialDomains, initialEnrichmentSources } from '../data/mockSources';
import { mockAlerts } from '../data/mockAlerts';
import { mockIncidents } from '../data/mockIncidents';
import { defaultCorrelationConfig } from '../data/mockNormalization';
import { simulatorEngine } from '../services/simulatorEngine';

interface SentinelState {
  domains: PrimaryDomain[];
  enrichmentSources: EnrichmentSource[];
  alerts: Alert[];
  incidents: Incident[];
  selectedIncidentId: string;
  correlationConfig: CorrelationConfig;
  isDemoMode: boolean;
  activeSourcesCount: number;
  totalSourcesCount: number;

  // Live Throughput Product Metrics
  eventsPerSec: number;
  totalEventsProcessed: number;
  alertsPerSec: number;
  processingLatencyMs: number;

  // Simulator
  simulatorRunning: boolean;
  simulatorRate: number;
  simulatorEvents: SimEvent[];
  selectedScenario: AttackScenario;
  startSimulator: () => void;
  pauseSimulator: () => void;
  resetSimulator: () => void;
  setSimulatorRate: (rate: number) => void;
  setSelectedScenario: (scenario: AttackScenario) => void;

  // Actions
  toggleDomain: (domainId: DomainType) => void;
  toggleSource: (domainId: DomainType, sourceId: string) => void;
  toggleEnrichmentSource: (sourceId: EnrichmentSourceType) => void;
  setSelectedIncidentId: (id: string) => void;
  toggleCorrelationRule: (ruleId: string) => void;
  updateCorrelationWindow: (mins: number) => void;
  updateMinSources: (count: number) => void;
  updateIncidentWeights: (incidentId: string, weights: RiskWeights) => void;
  updateAlertStatus: (
    alertId: string,
    status: 'New' | 'Investigating' | 'Resolved' | 'False Positive' | 'Confirmed Threat'
  ) => void;
  setIsDemoMode: (enabled: boolean) => void;
  loadDemoData: () => void;
}

const initialSimEvents: SimEvent[] = [
  {
    id: 'EVT-901',
    event_id: 'EVT-901',
    timestamp: '12:31:05',
    source: 'Endpoint Sensor',
    eventType: 'Suspicious process spawn (rundll32.exe)',
    event_type: 'process_execution',
    asset: 'HOST-042',
    severity: 'HIGH',
    mitre: 'T1055',
    mitre_technique: 'T1055 — Process Injection',
    detection_confidence: 88,
    raw_event: {
      EventID: 1,
      Computer: 'HOST-042',
      Image: 'C:\\Windows\\System32\\rundll32.exe',
      CommandLine: 'rundll32.exe advpack.dll,LaunchINFSection',
      User: 'SYSTEM',
    },
    normalized_event: {
      event_id: 'EVT-901',
      source: 'Endpoint Sensor',
      event_type: 'process_execution',
      asset: 'HOST-042',
      process: 'rundll32.exe',
      severity: 'high',
    },
    pipeline_stage: 'STAGE_2_PROCESS_INJECTION',
    correlation_note: 'Suspicious DLL invocation via rundll32.exe.',
  },
  {
    id: 'EVT-902',
    event_id: 'EVT-902',
    timestamp: '12:31:04',
    source: 'SIEM',
    eventType: 'PowerShell execution with encoded command',
    event_type: 'process_execution',
    asset: 'HOST-042',
    severity: 'MEDIUM',
    mitre: 'T1059.001',
    mitre_technique: 'T1059.001 — PowerShell',
    detection_confidence: 94,
    alert_id: 'ALT-1042',
    incident_id: 'INC-1042',
    raw_event: {
      EventID: 4104,
      Computer: 'HOST-042',
      CommandLine: 'powershell.exe -enc SQBFAFgA...',
      User: 'admin',
    },
    normalized_event: {
      event_id: 'EVT-902',
      source: 'SIEM',
      event_type: 'process_execution',
      asset: 'HOST-042',
      process: 'powershell.exe',
      severity: 'medium',
    },
    pipeline_stage: 'ALERT_GENERATED',
    correlation_note: 'Encoded execution correlated with ALT-1042.',
  },
  {
    id: 'EVT-903',
    event_id: 'EVT-903',
    timestamp: '12:30:58',
    source: 'Network Sensor',
    eventType: 'Outbound TCP connection to unclassified IP',
    event_type: 'network_connection',
    asset: 'HOST-042',
    severity: 'MEDIUM',
    mitre: 'T1071.001',
    mitre_technique: 'T1071.001 — Web Protocols',
    detection_confidence: 90,
    raw_event: {
      EventID: 3,
      Computer: 'HOST-042',
      DestinationIp: '198.51.100.42',
      DestinationPort: 443,
      Protocol: 'tcp',
    },
    normalized_event: {
      event_id: 'EVT-903',
      source: 'Network Sensor',
      event_type: 'network_connection',
      asset: 'HOST-042',
      dest_ip: '198.51.100.42',
      severity: 'medium',
    },
    pipeline_stage: 'STAGE_4_C2_NETWORK',
    correlation_note: 'Periodic beaconing behavior observed.',
  },
  {
    id: 'EVT-904',
    event_id: 'EVT-904',
    timestamp: '12:30:42',
    source: 'Satellite (JPL)',
    eventType: 'Subsystem thermal telemetry deviation (+26.8%)',
    event_type: 'telemetry_anomaly',
    asset: 'SAT-NOAA-19',
    severity: 'LOW',
    mitre: 'T1499',
    mitre_technique: 'T1499 — Endpoint DoS (Operational)',
    detection_confidence: 68,
    raw_event: {
      Spacecraft: 'SAT-NOAA-19',
      Subsystem: 'EPS_POWER_AND_THERMAL',
      TempDeviation: '+26.8%',
    },
    normalized_event: {
      event_id: 'EVT-904',
      source: 'Satellite (JPL)',
      event_type: 'telemetry_anomaly',
      asset: 'SAT-NOAA-19',
      deviation: '+26.8% thermal',
      severity: 'low',
    },
    pipeline_stage: 'TELEMETRY_ANOMALY_RECORDED',
    correlation_note: 'Operational space telemetry anomaly. Non-cyber isolated.',
  },
  {
    id: 'EVT-905',
    event_id: 'EVT-905',
    timestamp: '12:30:20',
    source: 'SIEM',
    eventType: 'Failed login burst (4 attempts against svc_database_admin)',
    event_type: 'authentication_failure',
    asset: 'HOST-042',
    severity: 'MEDIUM',
    mitre: 'T1110',
    mitre_technique: 'T1110 — Brute Force',
    detection_confidence: 87,
    alert_id: 'ALT-1043',
    raw_event: {
      EventID: 4625,
      Computer: 'HOST-042',
      TargetUserName: 'svc_database_admin',
      Status: '0xC000006D',
    },
    normalized_event: {
      event_id: 'EVT-905',
      source: 'SIEM',
      event_type: 'authentication_failure',
      asset: 'HOST-042',
      user: 'svc_database_admin',
      severity: 'medium',
    },
    pipeline_stage: 'STAGE_1_INITIAL_ACCESS',
    correlation_note: 'Multiple failed authentications within 45 seconds.',
  },
];

const SentinelContext = createContext<SentinelState | undefined>(undefined);

export const SentinelProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [domains, setDomains] = useState<PrimaryDomain[]>(initialDomains);
  const [enrichmentSources, setEnrichmentSources] = useState<EnrichmentSource[]>(initialEnrichmentSources);
  const [alerts, setAlerts] = useState<Alert[]>(mockAlerts);
  const [incidents, setIncidents] = useState<Incident[]>(mockIncidents);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('INC-1042');
  const [correlationConfig, setCorrelationConfig] = useState<CorrelationConfig>(defaultCorrelationConfig);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(true);

  // Live Throughput
  const [eventsPerSec, setEventsPerSec] = useState<number>(1248);
  const [totalEventsProcessed, setTotalEventsProcessed] = useState<number>(42810);
  const [alertsPerSec, setAlertsPerSec] = useState<number>(12);
  const [processingLatencyMs, setProcessingLatencyMs] = useState<number>(84);

  // Simulator State
  const [simulatorRunning, setSimulatorRunning] = useState<boolean>(false);
  const [simulatorRate, setSimulatorRate] = useState<number>(50);
  const [simulatorEvents, setSimulatorEvents] = useState<SimEvent[]>(initialSimEvents);
  const [selectedScenario, setSelectedScenario] = useState<AttackScenario>('multi_stage');

  // Progression index for sequence tracking
  const stageIndexRef = useRef<number>(0);

  
  // Poll Backend API
  useEffect(() => {
    if (!simulatorRunning) return;
    
    const pollApi = async () => {
      try {
        await fetch('http://127.0.0.1:8000/api/ingest', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ scenario: selectedScenario, sector: "Sector-4-North", clear_session: false })
        });
        await fetch('http://127.0.0.1:8000/api/correlate?sector=Sector-4-North', { method: 'POST' });
        
        const alertsRes = await fetch('http://127.0.0.1:8000/api/alerts');
        const alertsData = await alertsRes.json();
        
        if (alertsData.alerts && alertsData.alerts.length > 0) {
            const mappedAlerts = alertsData.alerts.map((a: any) => ({
                alertId: a.alert_id,
                timestamp: a.timestamp,
                title: 'Detected ' + a.domain + ' Anomaly',
                eventType: 'Telemetry Event',
                attackBehavior: 'Suspicious Activity',
                domain: a.domain.includes('siem') ? 'SIEM' : (a.domain.includes('satellite') ? 'SATELLITE' : 'SENSORS'),
                sourceId: a.domain,
                sourceName: a.source_name,
                asset: a.target_entity || a.sector || 'Unknown Asset',
                indicator: a.raw_payload.substring(0, 50) + '...',
                sourceSeverity: 'MEDIUM',
                priority: 'HIGH',
                priorityReason: 'Detected by backend STIX normalizer',
                confidence: 85,
                behavioralMatch: 'Correlated via spatio-temporal graph',
                mitreId: 'T1000',
                mitreName: 'Detected Activity',
                mitreTactic: 'Unknown',
                mitreDescription: 'Automatically parsed by ARES pipeline',
                whatHappened: a.raw_payload,
                evidenceTimeline: [{ time: a.timestamp, event: 'Alert Ingested', source: a.source_name, detail: 'Raw processing' }],
                recommendedAction: 'Review incident clusters for wargamed COAs',
                correlationStatus: 'CORRELATED',
                status: 'New',
                rawReference: `backend://${a.alert_id}`
            }));
            setAlerts(mappedAlerts);
        }

        const clustersRes = await fetch('http://127.0.0.1:8000/api/clusters');
        const clustersData = await clustersRes.json();
        
        if (clustersData.clusters && clustersData.clusters.length > 0) {
            const mappedIncidents = clustersData.clusters.map((c: any) => ({
                incidentId: c.cluster_id,
                title: 'Hybrid Cluster: ' + c.cluster_id,
                status: 'INVESTIGATING',
                priority: c.overall_severity,
                sentinelPriority: c.overall_severity,
                riskScore: Math.round(c.bayesian_threat_confidence * 100),
                severity: c.overall_severity,
                firstSeen: c.created_at,
                lastSeen: c.created_at,
                description: 'Multi-domain threat spanning ' + c.domains_involved.join(', '),
                primaryThreatActor: c.primary_threat_actor,
                mitreTactics: c.mitre_techniques.map((t: any) => t.tactic),
                affectedAssets: c.alerts.map((a: any) => a.name),
                domainsInvolved: c.domains_involved.map((d: string) => d.includes('siem') ? 'SIEM' : (d.includes('satellite') ? 'SATELLITE' : 'SENSORS')),
                correlatedAlertIds: c.alerts.map((a: any) => a.original_alert_id),
                riskFactors: {
                    evidenceStrength: 90,
                    assetCriticality: 85,
                    correlationStrength: c.bayesian_threat_confidence * 100,
                    threatIntelConfidence: c.attribution_confidence * 100,
                    temporalCorrelation: 95
                },
                timeline: c.mitre_techniques.map((t: any) => ({
                    time: c.created_at,
                    stage: t.tactic,
                    description: t.name,
                    source: 'MITRE Correlation Engine',
                    mitre: t.technique_id
                }))
            }));
            setIncidents(mappedIncidents);
            if (mappedIncidents.length > 0) {
               setSelectedIncidentId(mappedIncidents[0].incidentId);
            }
        }
      } catch (err) {
        console.error("Backend fetch error:", err);
      }
    };

    const timer = setInterval(pollApi, 2000);
    return () => clearInterval(timer);
  }, [simulatorRunning, selectedScenario]);


  // Actions
  const startSimulator = () => setSimulatorRunning(true);
  const pauseSimulator = () => setSimulatorRunning(false);
  const resetSimulator = () => {
    setSimulatorRunning(false);
    stageIndexRef.current = 0;
    setSimulatorEvents(initialSimEvents);
    setAlerts(mockAlerts);
    setIncidents(mockIncidents);
    setTotalEventsProcessed(42810);
    setEventsPerSec(1248);
    setAlertsPerSec(12);
    setProcessingLatencyMs(84);
  };

  const updateAlertStatus = (
    alertId: string,
    status: 'New' | 'Investigating' | 'Resolved' | 'False Positive' | 'Confirmed Threat'
  ) => {
    setAlerts((prev) =>
      prev.map((a) => (a.alertId === alertId ? { ...a, status } : a))
    );

    // Synchronize with incidents if applicable
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.correlatedAlertIds.includes(alertId)) {
          if (status === 'Resolved' || status === 'False Positive') {
            // Check if all alerts are resolved/FP
            return { ...inc, status: 'RESOLVED' as const };
          } else if (status === 'Confirmed Threat') {
            return { ...inc, status: 'INVESTIGATING' as const, priority: 'CRITICAL' as const };
          }
        }
        return inc;
      })
    );
  };

  // Toggle entire domain
  const toggleDomain = (domainId: DomainType) => {
    setDomains((prev) =>
      prev.map((dom) => {
        if (dom.id !== domainId) return dom;
        const newEnabled = !dom.enabled;
        return {
          ...dom,
          enabled: newEnabled,
          status: newEnabled ? 'OPERATIONAL' : 'DISABLED',
          sources: dom.sources.map((src) => ({
            ...src,
            status: newEnabled ? (src.enabled ? 'OPERATIONAL' : 'DISABLED') : 'DISABLED',
          })),
        };
      })
    );
  };

  // Toggle individual source
  const toggleSource = (domainId: DomainType, sourceId: string) => {
    setDomains((prev) =>
      prev.map((dom) => {
        if (dom.id !== domainId) return dom;
        return {
          ...dom,
          sources: dom.sources.map((src) => {
            if (src.id !== sourceId) return src;
            const newEnabled = !src.enabled;
            return {
              ...src,
              enabled: newEnabled,
              status: newEnabled && dom.enabled ? 'OPERATIONAL' : 'DISABLED',
            };
          }),
        };
      })
    );
  };

  // Toggle enrichment source
  const toggleEnrichmentSource = (sourceId: EnrichmentSourceType) => {
    setEnrichmentSources((prev) =>
      prev.map((src) => {
        if (src.id !== sourceId) return src;
        const newEnabled = !src.enabled;
        return {
          ...src,
          enabled: newEnabled,
          status: newEnabled ? 'OPERATIONAL' : 'DISABLED',
        };
      })
    );
  };

  const toggleCorrelationRule = (ruleId: string) => {
    setCorrelationConfig((prev) => ({
      ...prev,
      rules: prev.rules.map((r) => (r.ruleId === ruleId ? { ...r, enabled: !r.enabled } : r)),
    }));
  };

  const updateCorrelationWindow = (mins: number) => {
    setCorrelationConfig((prev) => ({ ...prev, windowMinutes: mins }));
  };

  const updateMinSources = (count: number) => {
    setCorrelationConfig((prev) => ({ ...prev, minCorroboratingSources: count }));
  };

  const updateIncidentWeights = (incidentId: string, weights: RiskWeights) => {
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.incidentId !== incidentId) return inc;
        const f = inc.riskFactors;
        const computedScore = Math.round(
          f.evidenceStrength * weights.evidenceStrength +
          f.assetCriticality * weights.assetCriticality +
          f.correlationStrength * weights.correlationStrength +
          f.threatIntelConfidence * weights.threatIntelConfidence +
          f.temporalCorrelation * weights.temporalCorrelation
        );
        let priority: Incident['priority'] = 'LOW';
        if (computedScore >= 85) priority = 'CRITICAL';
        else if (computedScore >= 65) priority = 'HIGH';
        else if (computedScore >= 40) priority = 'MEDIUM';

        return {
          ...inc,
          riskScore: computedScore,
          priority,
          sentinelPriority: priority,
        };
      })
    );
  };

  const loadDemoData = () => {
    setDomains(initialDomains);
    setEnrichmentSources(initialEnrichmentSources);
    setAlerts(mockAlerts);
    setIncidents(mockIncidents);
    setSelectedIncidentId('INC-1042');
    setCorrelationConfig(defaultCorrelationConfig);
    setIsDemoMode(true);
    setEventsPerSec(1248);
    setTotalEventsProcessed(42810);
    setAlertsPerSec(12);
    setProcessingLatencyMs(84);
  };

  const { activeSourcesCount, totalSourcesCount } = useMemo(() => {
    let active = 0;
    let total = 0;
    domains.forEach((dom) => {
      dom.sources.forEach((src) => {
        total += 1;
        if (dom.enabled && src.enabled) {
          active += 1;
        }
      });
    });
    return { activeSourcesCount: active, totalSourcesCount: total };
  }, [domains]);

  return (
    <SentinelContext.Provider
      value={{
        domains,
        enrichmentSources,
        alerts,
        incidents,
        selectedIncidentId,
        correlationConfig,
        isDemoMode,
        activeSourcesCount,
        totalSourcesCount,
        eventsPerSec,
        totalEventsProcessed,
        alertsPerSec,
        processingLatencyMs,
        simulatorRunning,
        simulatorRate,
        simulatorEvents,
        selectedScenario,
        startSimulator,
        pauseSimulator,
        resetSimulator,
        setSimulatorRate,
        setSelectedScenario,
        toggleDomain,
        toggleSource,
        toggleEnrichmentSource,
        setSelectedIncidentId,
        toggleCorrelationRule,
        updateCorrelationWindow,
        updateMinSources,
        updateIncidentWeights,
        updateAlertStatus,
        setIsDemoMode,
        loadDemoData,
      }}
    >
      {children}
    </SentinelContext.Provider>
  );
};

export const useSentinel = (): SentinelState => {
  const context = useContext(SentinelContext);
  if (!context) {
    throw new Error('useSentinel must be used within a SentinelProvider');
  }
  return context;
};
