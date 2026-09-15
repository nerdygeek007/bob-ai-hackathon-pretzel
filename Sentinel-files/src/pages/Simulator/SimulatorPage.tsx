import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { SimEvent, AttackScenario } from '../../types';
import {
  Play,
  Pause,
  RotateCcw,
  Clock,
  ChevronRight,
  ArrowRight,
  Shield,
  Layers,
  Search,
  ExternalLink,
} from 'lucide-react';

export const SimulatorPage: React.FC = () => {
  const {
    simulatorRunning,
    simulatorRate,
    simulatorEvents,
    selectedScenario,
    startSimulator,
    pauseSimulator,
    resetSimulator,
    setSimulatorRate,
    setSelectedScenario,
    eventsPerSec,
    totalEventsProcessed,
    alertsPerSec,
    processingLatencyMs,
  } = useSentinel();

  const [selectedEvent, setSelectedEvent] = useState<SimEvent | null>(null);

  const scenarioOptions: { value: AttackScenario; label: string; description: string }[] = [
    {
      value: 'multi_stage',
      label: 'Multi-Stage Attack',
      description: 'Correlated kill chain: Initial Access → Credential Dump → PowerShell → C2 Beaconing',
    },
    {
      value: 'brute_force',
      label: 'Brute Force',
      description: 'MITRE T1110: Rapid failed authentication burst targeting privileged service account',
    },
    {
      value: 'powershell',
      label: 'PowerShell Attack',
      description: 'MITRE T1059.001: Obfuscated base64 script execution from anomalous parent process',
    },
    {
      value: 'normal',
      label: 'Normal Traffic',
      description: 'Benign baseline telemetry (DNS, user authentication, routine scheduled tasks)',
    },
    {
      value: 'false_positive',
      label: 'False Positive',
      description: 'Authorized administrative backup script with bypass flag for analyst triage',
    },
    {
      value: 'satellite_anomaly',
      label: 'Satellite Anomaly',
      description: 'Subsystem thermal & voltage telemetry deviation (Non-cyber isolated safety logic)',
    },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#171717]">
            SIEM & Telemetry Event Simulator
          </h1>
          <p className="text-sm text-[#737373] mt-0.5">
            Generate synthetic high-velocity security events and observe live correlation in real-time
          </p>
        </div>

        {/* Status pill */}
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border ${
              simulatorRunning
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-neutral-100 text-neutral-600 border-neutral-200'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                simulatorRunning ? 'bg-emerald-500 animate-ping' : 'bg-neutral-400'
              }`}
            />
            {simulatorRunning ? 'Simulation Running' : 'Simulation Paused'}
          </span>
        </div>
      </div>

      {/* Simulator Control Panel */}
      <Card title="Simulation Controls" subtitle="Configure event playback rate and scenario dataset">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          {/* Action buttons */}
          <div className="flex items-center gap-2.5">
            {simulatorRunning ? (
              <button
                onClick={pauseSimulator}
                className="px-4 py-2 rounded-lg bg-[#000000] text-white hover:bg-neutral-800 text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer shadow-xs"
              >
                <Pause className="w-4 h-4 text-amber-400" />
                Pause
              </button>
            ) : (
              <button
                onClick={startSimulator}
                className="px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-700 text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer shadow-xs"
              >
                <Play className="w-4 h-4 fill-white" />
                Start Simulator
              </button>
            )}

            <button
              onClick={resetSimulator}
              className="px-3.5 py-2 rounded-lg border border-[#e5e5e5] bg-white text-[#171717] hover:bg-[#f5f5f5] text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-[#737373]" />
              Reset
            </button>
          </div>

          {/* Event Rate Selector (Prompt Section 12) */}
          <div>
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#737373] block mb-1.5">
              Event Generation Rate
            </span>
            <div className="flex items-center gap-1.5 bg-[#f5f5f5] p-1 rounded-lg border border-[#e5e5e5] w-fit">
              {[10, 50, 100].map((rate) => (
                <button
                  key={rate}
                  onClick={() => setSimulatorRate(rate)}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    simulatorRate === rate
                      ? 'bg-white text-[#171717] shadow-xs font-semibold'
                      : 'text-[#737373] hover:text-[#171717]'
                  }`}
                >
                  {rate} / sec
                </button>
              ))}
            </div>
          </div>

          {/* Scenario Dataset Selector (Feature 2) */}
          <div>
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#737373] block mb-1.5">
              Scenario Dataset
            </span>
            <select
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value as AttackScenario)}
              className="w-full p-2 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] text-xs font-semibold text-[#171717] focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600 cursor-pointer"
            >
              {scenarioOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Live Product Throughput Metrics (Prompt Section 13) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Events / Sec
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-[#171717] font-mono">
              {eventsPerSec.toLocaleString()}
            </span>
            <span className="text-xs text-[#737373]">events/sec</span>
          </div>
          <span className="text-[11px] text-[#737373] mt-1">Live streaming ingress rate</span>
        </div>

        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Events Processed
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-[#171717] font-mono">
              {totalEventsProcessed.toLocaleString()}
            </span>
            <span className="text-xs text-[#737373]">total</span>
          </div>
          <span className="text-[11px] text-[#737373] mt-1">Cumulative session count</span>
        </div>

        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Alerts / Sec
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-[#171717] font-mono">
              {alertsPerSec}
            </span>
            <span className="text-xs text-[#737373]">alerts/sec</span>
          </div>
          <span className="text-[11px] text-[#737373] mt-1">Correlation pipeline output</span>
        </div>

        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Processing Latency
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-emerald-700 font-mono">
              {processingLatencyMs}
            </span>
            <span className="text-xs text-[#737373]">ms</span>
          </div>
          <span className="text-[11px] text-emerald-700 font-medium mt-1">Optimal pipeline SLA</span>
        </div>
      </div>

      {/* Live Event Stream (Prompt Section 12) */}
      <Card
        title="Live Ingestion Stream"
        subtitle="Simulated incoming security events feeding into correlation engine (click any row to inspect raw vs. normalized data)"
        badge={
          <span className="text-xs font-mono text-[#737373] px-2 py-0.5 rounded bg-[#f5f5f5] border border-[#e5e5e5]">
            {simulatorEvents.length} events in buffer
          </span>
        }
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px] text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#e5e5e5] bg-[#f9fafb] text-[#737373] text-[11px] font-medium font-sans">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Asset</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">MITRE</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#e5e5e5]">
              {simulatorEvents.map((evt, idx) => (
                <tr
                  key={evt.id + '-' + idx}
                  onClick={() => setSelectedEvent(evt)}
                  className={`hover:bg-blue-50/50 cursor-pointer transition-colors group ${
                    idx === 0 && simulatorRunning ? 'bg-blue-50/40' : ''
                  }`}
                >
                  <td className="py-2.5 px-4 text-[#737373] whitespace-nowrap">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-[#a3a3a3]" />
                      {evt.timestamp}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 font-sans font-medium text-[#171717]">
                    {evt.source}
                  </td>
                  <td className="py-2.5 px-4 font-sans text-[#171717]">
                    {evt.eventType}
                  </td>
                  <td className="py-2.5 px-4 font-bold text-[#171717]">
                    {evt.asset}
                  </td>
                  <td className="py-2.5 px-4">
                    <SeverityBadge severity={evt.severity} size="sm" variant="source" />
                  </td>
                  <td className="py-2.5 px-4">
                    {evt.mitre ? (
                      <span className="text-[11px] px-2 py-0.5 rounded bg-[#f5f5f5] text-[#171717] border border-[#e5e5e5]">
                        {evt.mitre}
                      </span>
                    ) : (
                      <span className="text-[#a3a3a3]">—</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <span className="inline-flex items-center gap-1 text-[11px] text-blue-600 font-sans font-medium group-hover:underline">
                      Inspect <ChevronRight className="w-3 h-3" />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Feature 4: RAW EVENT → NORMALIZED EVENT VIEWER (DrawerPanel) */}
      <DrawerPanel
        isOpen={!!selectedEvent}
        onClose={() => setSelectedEvent(null)}
        title={`Event Inspection • ${selectedEvent?.id || selectedEvent?.event_id}`}
        subtitle={`Source: ${selectedEvent?.source} • Asset: ${selectedEvent?.asset} • ${selectedEvent?.timestamp}`}
        width="max-w-2xl"
      >
        {selectedEvent && (
          <div className="space-y-6 text-xs font-sans">
            {/* 1. Processing Relationship Pipeline */}
            <div>
              <span className="text-[11px] font-semibold text-[#737373] uppercase tracking-wider block mb-2">
                Processing Relationship Flow
              </span>
              <div className="p-3.5 rounded-xl bg-[#f9fafb] border border-[#e5e5e5]">
                <div className="flex items-center justify-between gap-1 text-[11px] font-medium text-[#171717] overflow-x-auto py-1">
                  <span className="px-2 py-1 rounded bg-white border border-[#e5e5e5] shrink-0 font-mono text-blue-700 font-bold">
                    RAW EVENT
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-[#a3a3a3] shrink-0" />
                  <span className="px-2 py-1 rounded bg-white border border-[#e5e5e5] shrink-0 font-mono text-blue-700 font-bold">
                    NORMALIZED EVENT
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-[#a3a3a3] shrink-0" />
                  <span className="px-2 py-1 rounded bg-white border border-[#e5e5e5] shrink-0 font-mono text-purple-700 font-bold">
                    DETECTION / CORRELATION
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-[#a3a3a3] shrink-0" />
                  <span className="px-2 py-1 rounded bg-white border border-[#e5e5e5] shrink-0 font-mono text-amber-700 font-bold">
                    MITRE ATT&CK
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-[#a3a3a3] shrink-0" />
                  <span className="px-2 py-1 rounded bg-blue-600 text-white shrink-0 font-mono font-bold shadow-xs">
                    SENTINEL-X PRIORITY
                  </span>
                </div>

                {selectedEvent.correlation_note && (
                  <p className="mt-2.5 pt-2.5 border-t border-[#e5e5e5] text-xs text-[#737373]">
                    <strong className="text-[#171717]">Pipeline Stage Assessment: </strong>
                    {selectedEvent.correlation_note}
                  </p>
                )}
              </div>
            </div>

            {/* 2. Side-by-side or stacked Raw vs. Normalized Event */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* RAW EVENT */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] font-semibold text-[#737373] uppercase tracking-wider">
                    Raw Event (Ingested)
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#f5f5f5] text-[#737373] border border-[#e5e5e5]">
                    JSON Payload
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-neutral-900 text-neutral-100 font-mono text-[11px] overflow-x-auto max-h-[320px] leading-relaxed">
                  <pre>
                    {JSON.stringify(
                      selectedEvent.raw_event || {
                        EventID: 4104,
                        Computer: selectedEvent.asset,
                        Source: selectedEvent.source,
                        EventType: selectedEvent.eventType,
                        Timestamp: selectedEvent.timestamp,
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>

              {/* NORMALIZED EVENT */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] font-semibold text-[#737373] uppercase tracking-wider">
                    Normalized Event (Canonical)
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                    Sentinel Canonical Schema
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-neutral-900 text-neutral-100 font-mono text-[11px] overflow-x-auto max-h-[320px] leading-relaxed">
                  <pre>
                    {JSON.stringify(
                      selectedEvent.normalized_event || {
                        event_id: selectedEvent.id || selectedEvent.event_id,
                        timestamp: selectedEvent.timestamp,
                        source: selectedEvent.source,
                        event_type: selectedEvent.event_type || selectedEvent.eventType,
                        asset: selectedEvent.asset,
                        severity: selectedEvent.severity.toLowerCase(),
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>
            </div>

            {/* 3. MITRE ATT&CK & Sentinel-X Correlation Enrichment */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl bg-[#f9fafb] border border-[#e5e5e5]">
              <div>
                <span className="text-[10px] text-[#737373] block uppercase font-medium">
                  MITRE Technique
                </span>
                <span className="font-mono font-bold text-xs text-[#171717] mt-0.5 block">
                  {selectedEvent.mitre_technique || selectedEvent.mitre || 'Unmapped / Baseline'}
                </span>
              </div>

              <div>
                <span className="text-[10px] text-[#737373] block uppercase font-medium">
                  Detection Confidence
                </span>
                <span className="font-mono font-bold text-xs text-[#171717] mt-0.5 block">
                  {selectedEvent.detection_confidence ? `${selectedEvent.detection_confidence}%` : '65%'}
                </span>
              </div>

              <div>
                <span className="text-[10px] text-[#737373] block uppercase font-medium">
                  Alert Generation
                </span>
                {selectedEvent.alert_id ? (
                  <span className="inline-flex items-center gap-1 font-mono font-bold text-xs text-blue-700 mt-0.5">
                    {selectedEvent.alert_id} (Correlated)
                  </span>
                ) : (
                  <span className="text-xs text-[#737373] mt-0.5 block">
                    No alert triggered
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
