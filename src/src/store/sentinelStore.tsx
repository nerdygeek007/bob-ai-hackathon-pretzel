import React, { createContext, useContext, useState, useMemo, ReactNode } from 'react';
import {
  PrimaryDomain,
  EnrichmentSource,
  Alert,
  Incident,
  CorrelationConfig,
  DomainType,
  EnrichmentSourceType,
  RiskWeights,
  MitreMappingResult,
} from '../types';
import { mitreService, AlertClusterPayload } from '../services/mitreService';
import { initialDomains, initialEnrichmentSources } from '../data/mockSources';
import { mockAlerts } from '../data/mockAlerts';
import { mockIncidents } from '../data/mockIncidents';
import { defaultCorrelationConfig } from '../data/mockNormalization';

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

  // MITRE RAG state
  mitreMappings: MitreMappingResult[];
  mitreMappingLoading: boolean;
  mitreMappingError: string | null;

  // Actions
  toggleDomain: (domainId: DomainType) => void;
  toggleSource: (domainId: DomainType, sourceId: string) => void;
  toggleEnrichmentSource: (sourceId: EnrichmentSourceType) => void;
  setSelectedIncidentId: (id: string) => void;
  toggleCorrelationRule: (ruleId: string) => void;
  updateCorrelationWindow: (mins: number) => void;
  updateMinSources: (count: number) => void;
  updateIncidentWeights: (incidentId: string, weights: RiskWeights) => void;
  loadDemoData: () => void;
  runMitreMapping: (payloads: AlertClusterPayload[]) => Promise<void>;
}

const SentinelContext = createContext<SentinelState | undefined>(undefined);

export const SentinelProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [domains, setDomains] = useState<PrimaryDomain[]>(initialDomains);
  const [enrichmentSources, setEnrichmentSources] = useState<EnrichmentSource[]>(initialEnrichmentSources);
  const [alerts, setAlerts] = useState<Alert[]>(mockAlerts);
  const [incidents, setIncidents] = useState<Incident[]>(mockIncidents);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('INC-0042');
  const [correlationConfig, setCorrelationConfig] = useState<CorrelationConfig>(defaultCorrelationConfig);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(true);

  // MITRE RAG state
  const [mitreMappings, setMitreMappings] = useState<MitreMappingResult[]>(
    mitreService.getMockResults()
  );
  const [mitreMappingLoading, setMitreMappingLoading] = useState<boolean>(false);
  const [mitreMappingError, setMitreMappingError] = useState<string | null>(null);

  const runMitreMapping = async (payloads: AlertClusterPayload[]) => {
    setMitreMappingLoading(true);
    setMitreMappingError(null);
    try {
      const results = await mitreService.mapClusters(payloads);
      setMitreMappings(results);
    } catch (err) {
      setMitreMappingError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setMitreMappingLoading(false);
    }
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
            // If domain disabled, sources are disabled for ingestion
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

  // Correlation config actions
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
    setSelectedIncidentId('INC-0042');
    setCorrelationConfig(defaultCorrelationConfig);
    setIsDemoMode(true);
    setMitreMappings(mitreService.getMockResults());
    setMitreMappingError(null);
  };

  // Calculate active sources count
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
        mitreMappings,
        mitreMappingLoading,
        mitreMappingError,
        toggleDomain,
        toggleSource,
        toggleEnrichmentSource,
        setSelectedIncidentId,
        toggleCorrelationRule,
        updateCorrelationWindow,
        updateMinSources,
        updateIncidentWeights,
        loadDemoData,
        runMitreMapping,
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
