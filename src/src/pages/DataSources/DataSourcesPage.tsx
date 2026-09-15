import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { Toggle } from '../../components/ui/Toggle';
import { StatusIndicator } from '../../components/ui/StatusIndicator';
import { SourceConfigDrawer } from './SourceConfigDrawer';
import { SubSource, DomainType, EnrichmentSourceType } from '../../types';
import {
  Database,
  Radio,
  Cpu,
  Layers,
  Settings2,
  Activity,
  AlertCircle,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';

export const DataSourcesPage: React.FC = () => {
  const {
    domains,
    enrichmentSources,
    toggleDomain,
    toggleSource,
    toggleEnrichmentSource,
  } = useSentinel();

  const [activeTabDomain, setActiveTabDomain] = useState<DomainType>('SIEM');
  const [selectedSourceForConfig, setSelectedSourceForConfig] = useState<SubSource | null>(null);

  const activeDomain = domains.find((d) => d.id === activeTabDomain) || domains[0];

  const getDomainIcon = (id: DomainType) => {
    switch (id) {
      case 'SIEM':
        return <Database className="w-6 h-6 text-sky-400" />;
      case 'SATELLITE_SPACE':
        return <Radio className="w-6 h-6 text-purple-400" />;
      case 'SENSORS':
        return <Cpu className="w-6 h-6 text-emerald-400" />;
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          PRIMARY DATA SOURCES & INGESTION STREAMS
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure the 3 primary operational evidence domains and enrichment intelligence feeds
        </p>
      </div>

      {/* TOP: 3 Primary Domain Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {domains.map((dom) => {
          const activeCount = dom.sources.filter((s) => s.enabled).length;
          const totalCount = dom.sources.length;
          const isSelected = activeTabDomain === dom.id;

          return (
            <div
              key={dom.id}
              className={`bg-[#111827] border rounded-sm p-5 shadow-xl transition-all relative flex flex-col justify-between ${
                dom.enabled
                  ? isSelected
                    ? 'border-cyan-500/80 shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                    : 'border-[#1f293d] hover:border-slate-600'
                  : 'border-slate-800 opacity-65'
              }`}
            >
              <div>
                {/* Header with Title & Master Toggle */}
                <div className="flex items-start justify-between gap-2 pb-4 border-b border-[#1f293d]">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                      {getDomainIcon(dom.id)}
                    </div>
                    <div>
                      <h2 className="text-base font-black font-mono tracking-wider text-slate-100 uppercase">
                        {dom.label}
                      </h2>
                      <p className="text-[11px] text-slate-400 font-mono mt-0.5">{dom.subtitle}</p>
                    </div>
                  </div>
                  <Toggle
                    checked={dom.enabled}
                    onChange={() => toggleDomain(dom.id)}
                    size="md"
                  />
                </div>

                {/* Domain Stats Strip */}
                <div className="py-4 space-y-2.5 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Active Sources:</span>
                    <span className="font-bold text-cyan-400">
                      {dom.enabled ? `${activeCount}/${totalCount}` : '0/' + totalCount + ' (Domain OFF)'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">
                      {dom.id === 'SATELLITE_SPACE' ? 'Telemetry Records:' : 'Events Processed:'}
                    </span>
                    <span className="font-bold text-slate-200">
                      {dom.totalRecords.toLocaleString()}
                    </span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Status:</span>
                    <StatusIndicator status={dom.status} />
                  </div>
                </div>
              </div>

              {/* View Sources Button */}
              <button
                onClick={() => setActiveTabDomain(dom.id)}
                className={`w-full py-2 px-3 rounded text-xs font-mono font-bold tracking-wider uppercase transition-colors flex items-center justify-center gap-2 cursor-pointer border ${
                  isSelected
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-700'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                }`}
              >
                <span>{isSelected ? '✓ Viewing Sub-Sources' : 'View Sources'}</span>
              </button>
            </div>
          );
        })}
      </div>

      {/* SUB-SOURCES OF SELECTED DOMAIN */}
      <Card
        title={`${activeDomain.label} — Individual Source Toggles & Adapters`}
        subtitle={`${activeDomain.sources.length} public/actual telemetry feeds`}
        badge={
          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
            {activeDomain.sources.filter((s) => s.enabled && activeDomain.enabled).length} Active
          </span>
        }
      >
        <div className="space-y-4">
          {!activeDomain.enabled && (
            <div className="p-3 bg-red-950/40 border border-red-800/80 rounded flex items-center gap-2 text-xs font-mono text-red-300">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>
                <strong>MASTER DOMAIN OFF:</strong> Ingestion for {activeDomain.label} is currently
                stopped. All sub-sources are disabled from new correlation passes.
              </span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            {activeDomain.sources.map((src) => {
              const isSourceOperational = src.enabled && activeDomain.enabled;

              return (
                <div
                  key={src.id}
                  className={`p-4 rounded border transition-all ${
                    isSourceOperational
                      ? 'bg-slate-900/80 border-slate-700/80 shadow-sm'
                      : 'bg-slate-950/60 border-slate-800 opacity-60'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-100 text-sm">{src.name}</span>
                        <span
                          className={`text-[9px] px-1.5 py-0.2 rounded font-bold border ${
                            isSourceOperational
                              ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                              : 'bg-slate-800 text-slate-400 border-slate-700'
                          }`}
                        >
                          {isSourceOperational ? 'ACTIVE' : 'DISABLED'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{src.description}</p>
                    </div>

                    <Toggle
                      checked={src.enabled}
                      disabled={!activeDomain.enabled}
                      onChange={() => toggleSource(activeDomain.id, src.id)}
                      size="sm"
                    />
                  </div>

                  {/* Telemetry metrics or Disabled warning */}
                  <div className="py-3 text-[11px] space-y-1">
                    {isSourceOperational ? (
                      <>
                        <div className="flex justify-between text-slate-400">
                          <span>Last Ingestion:</span>
                          <span className="text-slate-200">
                            {src.lastIngestion ? new Date(src.lastIngestion).toLocaleTimeString() : '2 min ago'}
                          </span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Records Ingested:</span>
                          <span className="text-cyan-400 font-bold">
                            {src.recordsProcessed.toLocaleString()}
                          </span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Ingestion Rate / Latency:</span>
                          <span className="text-slate-300">
                            {src.eventsPerMinute} ev/m • {src.latencyMs} ms
                          </span>
                        </div>
                      </>
                    ) : (
                      <div className="text-slate-500 italic py-1">
                        ○ DISABLED — This source is excluded from new ingestion and correlation.
                        Historical telemetry remains stored.
                      </div>
                    )}
                  </div>

                  {/* Action buttons */}
                  <div className="pt-2 flex items-center gap-2 border-t border-slate-800/80">
                    <button
                      onClick={() => setSelectedSourceForConfig(src)}
                      className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer"
                    >
                      <Settings2 className="w-3.5 h-3.5 text-cyan-400" />
                      Configure
                    </button>

                    {isSourceOperational && (
                      <button
                        onClick={() => setSelectedSourceForConfig(src)}
                        className="px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 border border-slate-800 transition-colors cursor-pointer"
                      >
                        <Activity className="w-3.5 h-3.5 text-emerald-400" />
                        Test Connection
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </Card>

      {/* BOTTOM: ENRICHMENT SOURCES (Strictly visually distinct from the 3 primary operational domains) */}
      <div className="pt-4 border-t-2 border-dashed border-[#1f293d]">
        <div className="mb-4">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold font-mono text-slate-100 uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-5 h-5 text-amber-400" />
              ENRICHMENT SOURCES
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800 font-mono font-bold">
              NOT PRIMARY OPERATIONAL DOMAINS
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            MITRE ATT&CK and CISA KEV enrich and contextualize evidence streams; they do not ingest
            live telemetry events.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {enrichmentSources.map((enrich) => (
            <div
              key={enrich.id}
              className="bg-[#111827]/90 border border-amber-900/40 rounded-sm p-5 shadow-lg flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-black font-mono text-amber-300 uppercase">
                        {enrich.label}
                      </span>
                      <StatusIndicator status={enrich.status} />
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono mt-1">
                      {enrich.description}
                    </p>
                  </div>
                  <Toggle
                    checked={enrich.enabled}
                    onChange={() => toggleEnrichmentSource(enrich.id)}
                    size="md"
                  />
                </div>

                <div className="py-3 space-y-1.5 font-mono text-xs">
                  <div className="flex justify-between text-slate-400">
                    <span>Catalog Entries:</span>
                    <span className="text-amber-300 font-bold">
                      {enrich.totalEntries.toLocaleString()} items
                    </span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Last Catalog Synchronization:</span>
                    <span className="text-slate-300">
                      {new Date(enrich.lastSync).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </div>

              <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
                <span>Enrichment status: {enrich.enabled ? 'Active contextual lookup' : 'Muted'}</span>
                <span className="text-cyan-400 font-bold">
                  {enrich.id === 'mitre_attack' ? 'CTI Matrix' : 'KEV Catalog'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Configuration Drawer */}
      <SourceConfigDrawer
        source={selectedSourceForConfig}
        isOpen={!!selectedSourceForConfig}
        onClose={() => setSelectedSourceForConfig(null)}
        onToggle={toggleSource}
      />
    </div>
  );
};
