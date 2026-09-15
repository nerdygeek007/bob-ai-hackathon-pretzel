import React, { createContext, useContext, useState, useMemo, useEffect, ReactNode } from 'react';
import {
  PrimaryDomain,
  EnrichmentSource,
  Alert,
  Incident,
  CorrelationConfig,
  DomainType,
  EnrichmentSourceType,
  RiskWeights,
  SeverityLevel,
} from '../types';
import { initialDomains, initialEnrichmentSources } from '../data/mockSources';
import { mockAlerts } from '../data/mockAlerts';
import { mockIncidents } from '../data/mockIncidents';
import { defaultCorrelationConfig } from '../data/mockNormalization';

export interface SimEvent {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  asset: string;
  severity: SeverityLevel;
  mitre?: string;
}

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
  startSimulator: () => void;
  pauseSimulator: () => void;
  resetSimulator: () => void;
  setSimulatorRate: (rate: number) => void;

  // Actions
  toggleDomain: (domainId: DomainType) => void;
  toggleSource: (domainId: DomainType, sourceId: string) => void;
  toggleEnrichmentSource: (sourceId: EnrichmentSourceType) => void;
  setSelectedIncidentId: (id: string) => void;
  toggleCorrelationRule: (ruleId: string) => void;
  updateCorrelationWindow: (mins: number) => void;
  updateMinSources: (count: number) => void;
  updateIncidentWeights: (incidentId: string, weights: RiskWeights) => void;
  updateAlertStatus: (alertId: string, status: 'New' | 'Investigating' | 'Resolved' | 'False Positive') => void;
  setIsDemoMode: (enabled: boolean) => void;
  loadDemoData: () => void;
}

const sampleSimEventsPool: Omit<SimEvent, 'id' | 'timestamp'>[] = [
  { source: 'SIEM', eventType: 'PowerShell execution', asset: 'HOST-042', severity: 'MEDIUM', mitre: 'T1059.001' },
  { source: 'Endpoint', eventType: 'Suspicious process spawn (rundll32.exe)', asset: 'HOST-042', severity: 'HIGH', mitre: 'T1055' },
  { source: 'Network Sensor', eventType: 'Outbound TCP connection to 198.51.100.42', asset: 'HOST-042', severity: 'MEDIUM', mitre: 'T1071.001' },
  { source: 'Endpoint', eventType: 'Kerberos pre-authentication failure', asset: 'HOST-042', severity: 'LOW', mitre: 'T1110' },
  { source: 'SIEM', eventType: 'Windows Event Log cleared (ID 1102)', asset: 'DC-PRIMARY-01', severity: 'HIGH', mitre: 'T1070.001' },
  { source: 'Network Sensor', eventType: 'External reconnaissance probe', asset: 'GATEWAY-FW-01', severity: 'LOW', mitre: 'T1046' },
  { source: 'Satellite (JPL)', eventType: 'Subsystem thermal telemetry deviation', asset: 'SAT-NOAA-19', severity: 'MEDIUM', mitre: 'T1499' },
  { source: 'Endpoint', eventType: 'LSASS process memory access request', asset: 'HOST-042', severity: 'CRITICAL', mitre: 'T1003.001' },
  { source: 'SIEM', eventType: 'Privilege escalation via SeDebugPrivilege', asset: 'HOST-042', severity: 'HIGH', mitre: 'T1078' },
];

const initialSimEvents: SimEvent[] = [
  { id: 'EVT-901', timestamp: '12:31:05', source: 'Endpoint', eventType: 'Suspicious process', asset: 'HOST-042', severity: 'HIGH', mitre: 'T1055' },
  { id: 'EVT-902', timestamp: '12:31:04', source: 'SIEM', eventType: 'PowerShell execution', asset: 'HOST-042', severity: 'MEDIUM', mitre: 'T1059.001' },
  { id: 'EVT-903', timestamp: '12:30:58', source: 'Network Sensor', eventType: 'Beaconing connection', asset: 'HOST-042', severity: 'MEDIUM', mitre: 'T1071' },
  { id: 'EVT-904', timestamp: '12:30:42', source: 'Satellite (JPL)', eventType: 'Telemetry anomaly (+26.8%)', asset: 'SAT-NOAA-19', severity: 'LOW', mitre: 'T1499' },
  { id: 'EVT-905', timestamp: '12:30:20', source: 'SIEM', eventType: 'Failed login burst (4 attempts)', asset: 'HOST-042', severity: 'MEDIUM', mitre: 'T1110' },
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

  // Simulator
  const [simulatorRunning, setSimulatorRunning] = useState<boolean>(false);
  const [simulatorRate, setSimulatorRate] = useState<number>(50);
  const [simulatorEvents, setSimulatorEvents] = useState<SimEvent[]>(initialSimEvents);

  // Simulator live event generation loop
  useEffect(() => {
    if (!simulatorRunning) return;

    const intervalMs = Math.max(200, Math.floor(1000 / (simulatorRate / 10)));
    const timer = setInterval(() => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const sample = sampleSimEventsPool[Math.floor(Math.random() * sampleSimEventsPool.length)];

      const newSimEvent: SimEvent = {
        id: `EVT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: timeStr,
        ...sample,
      };

      setSimulatorEvents((prev) => [newSimEvent, ...prev.slice(0, 39)]);
      setTotalEventsProcessed((prev) => prev + Math.floor(simulatorRate / 5));

      // Fluctuations
      setEventsPerSec(1200 + Math.floor(Math.random() * 96) + (simulatorRate === 100 ? 300 : simulatorRate === 50 ? 50 : 0));
      setProcessingLatencyMs(80 + Math.floor(Math.random() * 12));
    }, intervalMs);

    return () => clearInterval(timer);
  }, [simulatorRunning, simulatorRate]);

  // Actions
  const startSimulator = () => setSimulatorRunning(true);
  const pauseSimulator = () => setSimulatorRunning(false);
  const resetSimulator = () => {
    setSimulatorRunning(false);
    setSimulatorEvents(initialSimEvents);
    setTotalEventsProcessed(42810);
    setEventsPerSec(1248);
  };

  const updateAlertStatus = (alertId: string, status: 'New' | 'Investigating' | 'Resolved' | 'False Positive') => {
    setAlerts((prev) =>
      prev.map((a) => (a.alertId === alertId ? { ...a, status } : a))
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
        startSimulator,
        pauseSimulator,
        resetSimulator,
        setSimulatorRate,
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
