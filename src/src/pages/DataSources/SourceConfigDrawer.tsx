import React, { useState } from 'react';
import { SubSource, DomainType } from '../../types';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { Toggle } from '../../components/ui/Toggle';
import { Check, RefreshCw, Server, ShieldCheck, Sliders, Database } from 'lucide-react';
import { ingestionService } from '../../services/ingestionService';

interface SourceConfigDrawerProps {
  source: SubSource | null;
  isOpen: boolean;
  onClose: () => void;
  onToggle: (domain: DomainType, sourceId: string) => void;
}

export const SourceConfigDrawer: React.FC<SourceConfigDrawerProps> = ({
  source,
  isOpen,
  onClose,
  onToggle,
}) => {
  const [activeTab, setActiveTab] = useState<'general' | 'network' | 'ingestion' | 'mapping'>('general');
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; latencyMs: number; message: string } | null>(null);

  if (!source) return null;

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    const result = await ingestionService.testConnection(source.name);
    setTestResult(result);
    setTestingConnection(false);
  };

  const isSatellite = source.domain === 'SATELLITE_SPACE';

  return (
    <DrawerPanel
      isOpen={isOpen}
      onClose={onClose}
      title={`Configure: ${source.name}`}
      subtitle={`Adapter ID: ${source.id} • ${source.domain.replace('_', ' / ')}`}
      width="max-w-xl"
    >
      <div className="space-y-5 text-xs">
        {/* Toggle Status Card */}
        <div className="p-4 bg-[#f9fafb] border border-[#e5e5e5] rounded-xl flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-[#171717] text-sm">Ingestion Status</span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                  source.enabled
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : 'bg-neutral-100 text-neutral-600 border border-neutral-200'
                }`}
              >
                {source.enabled ? 'Active' : 'Disabled'}
              </span>
            </div>
            <p className="text-[11px] text-[#737373] mt-1">
              {source.enabled
                ? 'Actively streaming and contributing to threat correlation.'
                : 'Excluded from new ingestion. Existing alerts remain available.'}
            </p>
          </div>
          <Toggle
            checked={source.enabled}
            onChange={() => onToggle(source.domain, source.id)}
            size="md"
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 border-b border-[#e5e5e5] pb-1">
          {[
            { id: 'general', label: 'General' },
            { id: 'network', label: 'Network' },
            { id: 'ingestion', label: isSatellite ? 'Telemetry' : 'Pipeline' },
            { id: 'mapping', label: 'Field Normalization' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors cursor-pointer ${
                activeTab === tab.id
                  ? 'bg-[#000000] text-white'
                  : 'text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* TAB 1: General */}
        {activeTab === 'general' && (
          <div className="space-y-4">
            <div>
              <label className="block text-[#737373] text-[11px] font-medium mb-1">Source Name</label>
              <input
                type="text"
                defaultValue={source.name}
                className="w-full bg-white border border-[#e5e5e5] rounded-md px-3 py-2 text-[#171717] focus:outline-none focus:border-blue-600"
              />
            </div>
            <div>
              <label className="block text-[#737373] text-[11px] font-medium mb-1">Description</label>
              <textarea
                rows={2}
                defaultValue={source.description}
                className="w-full bg-white border border-[#e5e5e5] rounded-md px-3 py-2 text-[#171717] focus:outline-none focus:border-blue-600"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[#737373] text-[11px] font-medium mb-1">Operational Domain</label>
                <input
                  type="text"
                  disabled
                  value={source.domain}
                  className="w-full bg-[#f5f5f5] border border-[#e5e5e5] rounded-md px-3 py-2 text-[#737373]"
                />
              </div>
              <div>
                <label className="block text-[#737373] text-[11px] font-medium mb-1">Source Adapter</label>
                <input
                  type="text"
                  disabled
                  value={`${source.sourceType}Adapter`}
                  className="w-full bg-[#f5f5f5] border border-[#e5e5e5] rounded-md px-3 py-2 text-[#737373]"
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Network / API */}
        {activeTab === 'network' && (
          <div className="space-y-4">
            <div>
              <label className="block text-[#737373] text-[11px] font-medium mb-1">Endpoint / Host</label>
              <input
                type="text"
                defaultValue={source.connectionHost || 'collector.internal.net'}
                className="w-full bg-white border border-[#e5e5e5] rounded-md px-3 py-2 text-[#171717] font-mono focus:outline-none focus:border-blue-600"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[#737373] text-[11px] font-medium mb-1">Protocol</label>
                <input
                  type="text"
                  defaultValue={source.protocol || 'gRPC / TLS'}
                  className="w-full bg-white border border-[#e5e5e5] rounded-md px-3 py-2 text-[#171717] font-mono focus:outline-none focus:border-blue-600"
                />
              </div>
              <div>
                <label className="block text-[#737373] text-[11px] font-medium mb-1">Ingestion Latency</label>
                <input
                  type="text"
                  disabled
                  value={`${source.latencyMs} ms`}
                  className="w-full bg-[#f5f5f5] border border-[#e5e5e5] rounded-md px-3 py-2 text-[#737373] font-mono"
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                onClick={handleTestConnection}
                disabled={testingConnection}
                className="px-3.5 py-2 rounded-lg bg-[#000000] hover:bg-neutral-800 text-white font-medium text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${testingConnection ? 'animate-spin' : ''}`} />
                {testingConnection ? 'Testing Connection...' : 'Test Adapter Handshake'}
              </button>
            </div>

            {testResult && (
              <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-900 text-xs flex items-start gap-2">
                <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold block">Handshake Successful ({testResult.latencyMs}ms)</span>
                  <p className="text-[11px] mt-0.5">{testResult.message}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 3: Ingestion / Telemetry */}
        {activeTab === 'ingestion' && (
          <div className="space-y-4">
            <div className="p-3.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] space-y-2">
              <span className="font-semibold text-xs text-[#171717] block">Pipeline Metrics</span>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-[#737373] text-[11px] block">Records Processed</span>
                  <span className="font-mono font-semibold text-[#171717]">{source.recordsProcessed.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-[#737373] text-[11px] block">Current Throughput</span>
                  <span className="font-mono font-semibold text-[#171717]">{source.eventsPerMinute.toLocaleString()} evt/min</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: Field Normalization Mapping */}
        {activeTab === 'mapping' && (
          <div className="space-y-3">
            <span className="text-xs font-semibold text-[#171717] block">
              Canonical Schema Mapping
            </span>
            <div className="border border-[#e5e5e5] rounded-lg overflow-hidden text-xs">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#e5e5e5] bg-[#f9fafb] text-[#737373] text-[11px]">
                    <th className="py-2 px-3">Canonical Field</th>
                    <th className="py-2 px-3">Source Payload Field</th>
                    <th className="py-2 px-3 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e5e5e5]">
                  <tr>
                    <td className="py-2 px-3 font-mono text-[#171717]">timestamp</td>
                    <td className="py-2 px-3 font-mono text-[#737373]">UtcTime / event_time</td>
                    <td className="py-2 px-3 text-right text-emerald-700 font-medium">Mapped</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-mono text-[#171717]">asset</td>
                    <td className="py-2 px-3 font-mono text-[#737373]">Computer / host.name</td>
                    <td className="py-2 px-3 text-right text-emerald-700 font-medium">Mapped</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-mono text-[#171717]">indicator</td>
                    <td className="py-2 px-3 font-mono text-[#737373]">CommandLine / process.command_line</td>
                    <td className="py-2 px-3 text-right text-emerald-700 font-medium">Mapped</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-mono text-[#171717]">eventType</td>
                    <td className="py-2 px-3 font-mono text-[#737373]">EventID / rule.name</td>
                    <td className="py-2 px-3 text-right text-emerald-700 font-medium">Mapped</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Footer actions */}
        <div className="pt-4 border-t border-[#e5e5e5] flex items-center justify-end gap-2">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg border border-[#e5e5e5] bg-white text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5] text-xs font-medium transition-colors cursor-pointer"
          >
            Close
          </button>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-[#000000] text-white hover:bg-neutral-800 text-xs font-medium transition-colors cursor-pointer"
          >
            Save Configuration
          </button>
        </div>
      </div>
    </DrawerPanel>
  );
};
