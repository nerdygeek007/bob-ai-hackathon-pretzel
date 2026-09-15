import React, { useState } from 'react';
import { mockTelemetry, telemetryTimeSeries } from '../../data/mockTelemetry';
import { Card } from '../../components/ui/Card';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
} from 'recharts';
import { Activity, Radio, AlertTriangle, CheckCircle2, ShieldAlert, Cpu } from 'lucide-react';

export const TelemetryPage: React.FC = () => {
  const [activeSourceFilter, setActiveSourceFilter] = useState<string>('ALL');

  const filteredTelemetry = mockTelemetry.filter((t) => {
    if (activeSourceFilter === 'ALL') return true;
    return t.sourceId === activeSourceFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          SATELLITE & SPACE TELEMETRY ANOMALY MONITOR
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          NASA JPL Spacecraft Anomaly Benchmark (Telemanom), ESA OPS-SAT telemetry, and OpenSky RF tracking
        </p>
      </div>

      {/* CRITICAL SAFETY DISCLAIMER BANNER (Prompt requirement) */}
      <div className="bg-amber-950/40 border border-amber-800/80 rounded-sm p-4 text-xs font-mono text-amber-200 flex items-start gap-3 shadow-lg">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-amber-300 font-bold block uppercase tracking-wider text-sm">
            Operational Telemetry Safety Principle:
          </strong>
          <p className="mt-1 leading-relaxed">
            "A telemetry anomaly does NOT automatically represent a cyber attack. It is initially
            classified strictly as a <strong>'Telemetry Anomaly'</strong>. It becomes elevated threat
            evidence only when correlated with independent cyber indicators (such as unauthorized uplink
            commands or network intrusions)."
          </p>
        </div>
      </div>

      {/* Telemetry Waveform Visualizer */}
      <Card
        title="NASA JPL Telemanom: P-1 Spectrometer Deviation Waveform"
        subtitle="Observed Value vs Expected Baseline vs Anomaly Score (SPACECRAFT-M-7)"
      >
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={telemetryTimeSeries} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <XAxis dataKey="time" stroke="#475569" fontSize={10} />
              <YAxis stroke="#475569" fontSize={10} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#1e293b',
                  borderRadius: 4,
                  fontSize: 11,
                  fontFamily: 'JetBrains Mono',
                }}
              />
              <Line
                type="monotone"
                dataKey="observed"
                name="Observed Value"
                stroke="#f97316"
                strokeWidth={2.5}
                dot={{ r: 4, fill: '#f97316' }}
              />
              <Line
                type="monotone"
                dataKey="expected"
                name="Expected Baseline"
                stroke="#38bdf8"
                strokeDasharray="4 4"
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="flex items-center justify-center gap-8 mt-3 pt-3 border-t border-slate-800 text-xs font-mono">
          <span className="flex items-center gap-2 text-orange-400 font-semibold">
            <span className="w-3 h-0.5 bg-orange-400" /> Observed Value (Anomalous Spike at 09:45)
          </span>
          <span className="flex items-center gap-2 text-sky-400 font-semibold">
            <span className="w-3 h-0.5 bg-sky-400 border-dashed" /> Expected Nominal Baseline (2.20)
          </span>
        </div>
      </Card>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 font-mono text-xs">
        <span className="text-slate-400 font-bold uppercase text-[11px]">Stream:</span>
        {[
          { id: 'ALL', label: 'All Space Sources' },
          { id: 'nasa_telemanom', label: 'NASA JPL Telemanom' },
          { id: 'esa_opssat', label: 'ESA OPS-SAT (Disabled/Historical)' },
          { id: 'opensky', label: 'OpenSky Network' },
        ].map((f) => (
          <button
            key={f.id}
            onClick={() => setActiveSourceFilter(f.id)}
            className={`px-3 py-1.5 rounded transition-colors font-semibold cursor-pointer ${
              activeSourceFilter === f.id
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Telemetry Records Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredTelemetry.map((rec) => (
          <div
            key={rec.recordId}
            className={`bg-[#111827] border rounded-sm p-4 font-mono text-xs space-y-3 ${
              rec.isAnomaly
                ? 'border-orange-900/60 shadow-md shadow-orange-950/30'
                : 'border-slate-800 opacity-80'
            }`}
          >
            <div className="flex items-start justify-between">
              <div>
                <span className="text-sm font-bold text-slate-100 block">{rec.sourceName}</span>
                <span className="text-[10px] text-slate-400 block mt-0.5">
                  ID: {rec.recordId} • {new Date(rec.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <span
                className={`text-[9px] px-2 py-0.5 rounded font-bold border ${
                  rec.isAnomaly
                    ? 'bg-orange-950 text-orange-400 border-orange-800'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {rec.operationalStatus}
              </span>
            </div>

            <div className="p-2.5 bg-slate-900/80 rounded border border-slate-800 space-y-1.5 text-[11px]">
              <div className="flex justify-between text-slate-400">
                <span>Vehicle / Target:</span>
                <span className="text-slate-200 font-bold">
                  {rec.spacecraftId || rec.aircraftId || '—'}
                </span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Parameter:</span>
                <span className="text-cyan-300 truncate max-w-[160px]">
                  {rec.telemetryParameter || '—'}
                </span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Observed vs Expected:</span>
                <span className="text-slate-200">
                  {rec.observedValue !== undefined ? rec.observedValue : '—'} /{' '}
                  {rec.expectedValue !== undefined ? rec.expectedValue : '—'}
                </span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Deviation:</span>
                <span
                  className={
                    rec.deviation && Math.abs(rec.deviation) > 1
                      ? 'text-orange-400 font-bold'
                      : 'text-slate-300'
                  }
                >
                  {rec.deviation !== undefined ? `+${rec.deviation}` : '—'}
                </span>
              </div>
            </div>

            {/* Anomaly score meter */}
            {rec.anomalyScore !== undefined && (
              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Telemetry Anomaly Score:</span>
                  <span
                    className={`font-bold ${
                      rec.anomalyScore >= 80
                        ? 'text-orange-400'
                        : rec.anomalyScore >= 40
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {rec.anomalyScore}%
                  </span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      rec.anomalyScore >= 80 ? 'bg-orange-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${rec.anomalyScore}%` }}
                  />
                </div>
              </div>
            )}

            {/* Corroboration chip */}
            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px]">
              <span className="text-slate-500">Cross-domain Corroboration:</span>
              <span
                className={
                  rec.corroboratedByCyberEvidence
                    ? 'text-cyan-400 font-bold flex items-center gap-1'
                    : 'text-slate-500'
                }
              >
                {rec.corroboratedByCyberEvidence ? '✓ Groundstation Corroborated' : 'None (Uncorrelated)'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
