import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { Toggle } from '../../components/ui/Toggle';
import { StatusIndicator } from '../../components/ui/StatusIndicator';
import { SourceConfigDrawer } from './SourceConfigDrawer';
import { SubSource, DomainType } from '../../types';
import {
  Database,
  Radio,
  Cpu,
  Settings,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { telemetryTimeSeries } from '../../data/mockTelemetry';

export const DataSourcesPage: React.FC = () => {
  const {
    domains,
    toggleDomain,
    toggleSource,
  } = useSentinel();

  const [selectedSourceForConfig, setSelectedSourceForConfig] = useState<SubSource | null>(null);

  const getDomainIcon = (id: DomainType) => {
    switch (id) {
      case 'SIEM':
        return <Database className="w-5 h-5 text-blue-600" />;
      case 'SATELLITE_SPACE':
        return <Radio className="w-5 h-5 text-blue-600" />;
      case 'SENSORS':
        return <Cpu className="w-5 h-5 text-blue-600" />;
    }
  };

  const getDomainEventsPerSec = (id: DomainType) => {
    switch (id) {
      case 'SIEM':
        return 820;
      case 'SATELLITE_SPACE':
        return 214;
      case 'SENSORS':
        return 214;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#171717]">
            Data Sources
          </h1>
          <p className="text-sm text-[#737373] mt-0.5">
            Active telemetry adapters across the 3 primary operational domains
          </p>
        </div>
        <div className="text-xs text-[#737373]">
          All adapters streaming in canonical normalized schema
        </div>
      </div>

      {/* 3 Primary Domain Cards (Prompt Section 10) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {domains.map((dom) => {
          const eventsRate = getDomainEventsPerSec(dom.id);

          return (
            <div
              key={dom.id}
              className={`bg-white border rounded-xl p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between transition-all ${
                dom.enabled ? 'border-[#e5e5e5]' : 'border-[#e5e5e5] opacity-60'
              }`}
            >
              <div>
                {/* Header: Icon, Domain Title, Master Toggle */}
                <div className="flex items-start justify-between pb-4 border-b border-[#e5e5e5]">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-[#f5f5f5] border border-[#e5e5e5]">
                      {getDomainIcon(dom.id)}
                    </div>
                    <div>
                      <h2 className="text-base font-bold text-[#171717]">
                        {dom.id === 'SIEM' ? 'SIEM' : dom.id === 'SATELLITE_SPACE' ? 'SATELLITE / SPACE' : 'SENSORS'}
                      </h2>
                      <p className="text-[11px] text-[#737373] mt-0.5">
                        {dom.sources.length} active feeds
                      </p>
                    </div>
                  </div>
                  <Toggle
                    checked={dom.enabled}
                    onChange={() => toggleDomain(dom.id)}
                    size="sm"
                  />
                </div>

                {/* Domain Quick Stats: Status & Events/sec */}
                <div className="py-3 flex items-center justify-between text-xs border-b border-[#e5e5e5]">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[#737373]">Status:</span>
                    <span className="font-semibold text-emerald-700 inline-flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      Connected
                    </span>
                  </div>
                  <div className="font-mono text-xs">
                    <span className="text-[#737373]">Events/sec: </span>
                    <strong className="text-[#171717]">{dom.enabled ? eventsRate : 0}</strong>
                  </div>
                </div>

                {/* Sub-sources list */}
                <div className="py-3 space-y-2">
                  <span className="text-[11px] font-semibold text-[#737373] uppercase tracking-wider block">
                    Connected Feeds
                  </span>
                  {dom.sources.map((src) => (
                    <div
                      key={src.id}
                      className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] flex items-center justify-between text-xs"
                    >
                      <div>
                        <span className="font-semibold text-[#171717] block">
                          {src.name}
                        </span>
                        <div className="flex items-center gap-2 text-[11px] text-[#737373] mt-0.5 font-mono">
                          <span>{src.eventsPerMinute.toLocaleString()} evt/min</span>
                          <span>•</span>
                          <span>{src.latencyMs}ms</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <Toggle
                          checked={src.enabled && dom.enabled}
                          onChange={() => toggleSource(dom.id, src.id)}
                          size="sm"
                        />
                        <button
                          onClick={() => setSelectedSourceForConfig(src)}
                          title="Configure adapter"
                          className="p-1.5 rounded-md hover:bg-white text-[#737373] hover:text-[#171717] border border-transparent hover:border-[#e5e5e5] transition-colors cursor-pointer"
                        >
                          <Settings className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Card Footer: Last Event */}
              <div className="pt-3 border-t border-[#e5e5e5] flex items-center justify-between text-[11px] text-[#737373]">
                <span>Last event: Just now</span>
                <button
                  onClick={() => setSelectedSourceForConfig(dom.sources[0])}
                  className="text-blue-600 hover:text-blue-700 font-medium inline-flex items-center gap-0.5 cursor-pointer"
                >
                  Configure <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Satellite Telemetry Operational Distinction Callout (Prompt Section 11) */}
      <Card
        title="Satellite Telemetry vs Confirmed Cyberattack"
        subtitle="Sentinel-X multi-domain isolation and corroboration policy"
      >
        <div className="p-4 rounded-xl bg-blue-50/50 border border-blue-200 text-xs space-y-3">
          <div className="flex items-center gap-2 text-blue-900 font-semibold text-sm">
            <Radio className="w-4 h-4 text-blue-600" />
            Operational Telemetry Policy Notice
          </div>
          <p className="text-blue-950 leading-relaxed">
            Satellite telemetry does not dominate the SOC alert queue. When NASA JPL or ESA OPS-SAT telemetry detects an anomaly (such as a thermal or bus voltage deviation), Sentinel-X treats it strictly as an <strong>operational telemetry anomaly</strong>.
          </p>
          <div className="p-3 bg-white rounded-lg border border-blue-200 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <span className="text-[#737373] block text-[11px]">Observed Telemetry</span>
              <span className="font-mono font-bold text-sm text-[#171717]">82.4°C</span>
            </div>
            <div>
              <span className="text-[#737373] block text-[11px]">Expected Baseline</span>
              <span className="font-mono font-bold text-sm text-[#171717]">65.0°C</span>
            </div>
            <div>
              <span className="text-[#737373] block text-[11px]">Deviation</span>
              <span className="font-mono font-bold text-sm text-amber-700">+26.8%</span>
            </div>
          </div>

          {/* Baseline vs Observed Deviation Curve */}
          <div className="p-3 bg-white rounded-lg border border-blue-200">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-2">
              <span className="text-xs font-semibold text-[#171717]">
                Thermal Radiator Temperature Curve (THR-MOD-04B)
              </span>
              <div className="flex items-center gap-3 text-[11px] text-[#737373]">
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-0.5 bg-blue-600 inline-block" /> Observed (°C)
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-0.5 border-t border-dashed border-[#a3a3a3] inline-block" /> Expected Baseline (65°C)
                </span>
              </div>
            </div>
            <div className="h-[160px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart
                  data={telemetryTimeSeries}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <XAxis
                    dataKey="time"
                    stroke="#a3a3a3"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#e5e5e5' }}
                  />
                  <YAxis
                    domain={[60, 90]}
                    stroke="#a3a3a3"
                    fontSize={10}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#ffffff',
                      borderColor: '#e5e5e5',
                      borderRadius: '8px',
                      fontSize: '12px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
                    }}
                    formatter={(value: any) => [`${value}°C`, 'Observed Temp']}
                  />
                  <ReferenceLine
                    y={65.0}
                    stroke="#a3a3a3"
                    strokeDasharray="3 3"
                    label={{
                      value: 'Baseline 65.0°C',
                      fill: '#737373',
                      fontSize: 10,
                      position: 'insideBottomRight',
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="value"
                    name="Observed"
                    stroke="#2563eb"
                    strokeWidth={2}
                    dot={{ r: 3, fill: '#2563eb' }}
                    activeDot={{ r: 5, fill: '#1d4ed8' }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
          <p className="text-[11px] text-blue-900 font-medium">
            <strong>Key Guarantee:</strong> A space telemetry anomaly alone will <em>never</em> automatically become a cyberattack alert without corroborating cyber evidence (such as unauthorized ground-station commands, brute force, or payload execution).
          </p>
        </div>
      </Card>

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
