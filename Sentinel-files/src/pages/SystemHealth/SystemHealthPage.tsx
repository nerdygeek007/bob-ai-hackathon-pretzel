import React from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { StatusIndicator } from '../../components/ui/StatusIndicator';
import {
  HeartPulse,
  Database,
  Radio,
  Cpu,
  Layers,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Server,
  Workflow,
} from 'lucide-react';

export const SystemHealthPage: React.FC = () => {
  const { domains, enrichmentSources } = useSentinel();

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          SYSTEM HEALTH & INGESTION TELEMETRY
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          Operational domain health status, source adapter latency metrics, and real-time architecture state
        </p>
      </div>

      {/* SECTION 27: DOMAIN HEALTH FIRST */}
      <div>
        <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-3 font-bold">
          Primary Operational Domains Health
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {domains.map((dom) => (
            <div
              key={dom.id}
              className={`p-5 rounded-sm border bg-[#111827] shadow-xl font-mono text-xs ${
                dom.enabled ? 'border-[#1f293d]' : 'border-slate-800 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-slate-900 rounded border border-slate-800 text-cyan-400">
                    {dom.id === 'SIEM' ? (
                      <Database className="w-5 h-5 text-sky-400" />
                    ) : dom.id === 'SATELLITE_SPACE' ? (
                      <Radio className="w-5 h-5 text-purple-400" />
                    ) : (
                      <Cpu className="w-5 h-5 text-emerald-400" />
                    )}
                  </div>
                  <div>
                    <h3 className="font-bold text-slate-100 text-sm">{dom.label}</h3>
                    <span className="text-[10px] text-slate-400 block">{dom.subtitle}</span>
                  </div>
                </div>
                <StatusIndicator status={dom.status} />
              </div>

              <div className="pt-3 space-y-1.5 text-[11px]">
                <div className="flex justify-between text-slate-400">
                  <span>Sub-sources Online:</span>
                  <span className="text-cyan-400 font-bold">
                    {dom.enabled ? `${dom.sources.filter((s) => s.enabled).length}/${dom.sources.length}` : '0/' + dom.sources.length}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Cumulative Records:</span>
                  <span className="text-slate-200 font-semibold">{dom.totalRecords.toLocaleString()}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* INDIVIDUAL SUB-SOURCES HEALTH TABLE */}
      <Card
        title="Individual Source Adapter Telemetry Metrics"
        subtitle="Latency, ingestion rates, and adapter error telemetry"
        noPadding
      >
        <div className="overflow-x-auto font-mono text-xs">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/70 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Source Name</th>
                <th className="py-3 px-4">Domain</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Latency</th>
                <th className="py-3 px-4">Rate (ev/min)</th>
                <th className="py-3 px-4">Records Processed</th>
                <th className="py-3 px-4">Last Ingestion</th>
                <th className="py-3 px-4 text-right">Errors</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {domains.flatMap((d) => d.sources).map((src) => {
                const isOp = src.enabled && domains.find((d) => d.id === src.domain)?.enabled;

                return (
                  <tr
                    key={src.id}
                    className={`transition-colors ${
                      isOp ? 'hover:bg-slate-800/40' : 'opacity-50 bg-slate-950/40'
                    }`}
                  >
                    <td className="py-3 px-4 font-bold text-slate-100">{src.name}</td>
                    <td className="py-3 px-4">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold border border-slate-700">
                        {src.domain.replace('_', ' / ')}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <StatusIndicator status={isOp ? 'OPERATIONAL' : 'DISABLED'} />
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {isOp ? `${src.latencyMs} ms` : '—'}
                    </td>
                    <td className="py-3 px-4 text-cyan-300 font-bold">
                      {isOp ? `${src.eventsPerMinute}` : '0'}
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      {isOp ? src.recordsProcessed.toLocaleString() : '0'}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {isOp && src.lastIngestion
                        ? new Date(src.lastIngestion).toLocaleTimeString()
                        : '—'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <span
                        className={
                          src.errorCount > 0
                            ? 'text-red-400 font-bold'
                            : 'text-slate-500 font-semibold'
                        }
                      >
                        {src.errorCount}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {/* SECTION 28: ARCHITECTURE VISUALIZATION */}
      <Card
        title="Sentinel-X End-to-End Operational Pipeline Architecture"
        subtitle="Live state representation with muted paths for disabled domains"
      >
        <div className="space-y-6 font-mono text-xs">
          <p className="text-slate-400 text-xs">
            Visual topology of the 3 primary evidence streams entering normalization, contextual
            enrichment, correlation, and BLUF generation:
          </p>

          <div className="p-6 bg-slate-950 rounded border border-slate-800 max-w-2xl mx-auto space-y-4 text-center">
            {/* 3 Primary Domains */}
            <div>
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold mb-2">
                PRIMARY OPERATIONAL EVIDENCE DOMAINS
              </span>
              <div className="grid grid-cols-3 gap-3">
                {domains.map((dom) => (
                  <div
                    key={dom.id}
                    className={`p-3 rounded border font-bold text-xs transition-all ${
                      dom.enabled
                        ? 'bg-slate-900 border-cyan-500/70 text-cyan-300 shadow-sm shadow-cyan-950'
                        : 'bg-slate-900/30 border-slate-800 text-slate-600 line-through'
                    }`}
                  >
                    {dom.label}
                    <span className="block text-[9px] font-normal text-slate-400 mt-0.5">
                      {dom.enabled ? 'ACTIVE STREAM' : 'MUTED'}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="text-cyan-500 text-sm py-0.5">↓</div>

            {/* Adapters */}
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-slate-300 font-bold max-w-sm mx-auto">
              SOURCE ADAPTERS (Domain Parsers)
            </div>

            <div className="text-cyan-500 text-sm py-0.5">↓</div>

            {/* Normalization */}
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-slate-300 font-bold max-w-sm mx-auto">
              SPARSE NORMALIZATION ENGINE (Canonical Model)
            </div>

            <div className="text-cyan-500 text-sm py-0.5">↓</div>

            {/* Contextual Enrichment split */}
            <div className="grid grid-cols-2 gap-3 max-w-sm mx-auto">
              <div
                className={`p-2 rounded border text-[11px] font-semibold ${
                  enrichmentSources.find((e) => e.id === 'mitre_attack')?.enabled
                    ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                    : 'bg-slate-900/30 border-slate-800 text-slate-600'
                }`}
              >
                MITRE ATT&CK CTI
              </div>
              <div
                className={`p-2 rounded border text-[11px] font-semibold ${
                  enrichmentSources.find((e) => e.id === 'cisa_kev')?.enabled
                    ? 'bg-red-950/40 border-red-800 text-red-300'
                    : 'bg-slate-900/30 border-slate-800 text-slate-600'
                }`}
              >
                CISA KEV Catalog
              </div>
            </div>

            <div className="text-cyan-500 text-sm py-0.5">↓</div>

            {/* Correlation */}
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-slate-300 font-bold max-w-sm mx-auto">
              DETERMINISTIC CROSS-SOURCE CORRELATION
            </div>

            <div className="text-cyan-500 text-sm py-0.5">↓</div>

            {/* Risk Engine */}
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-slate-300 font-bold max-w-sm mx-auto">
              EXPLAINABLE RISK & PRIORITISATION ENGINE
            </div>

            <div className="text-cyan-500 text-sm py-0.5">↓</div>

            {/* BLUF Report */}
            <div className="p-3 bg-cyan-950/80 rounded border-2 border-cyan-500 text-cyan-200 font-black text-sm max-w-sm mx-auto shadow-md shadow-cyan-950">
              COMMANDER BLUF BRIEFING
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};
