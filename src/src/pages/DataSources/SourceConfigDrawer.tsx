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
  const [activeTab, setActiveTab] = useState<'general' | 'network' | 'ingestion' | 'mapping'>(
    'general'
  );
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; latencyMs: number; message: string } | null>(
    null
  );

  if (!source) return null;

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    const result = await ingestionService.testConnection(source.name);
    setTestResult(result);
    setTestingConnection(false);
  };

  const isSiem = source.domain === 'SIEM';
  const isSatellite = source.domain === 'SATELLITE_SPACE';
  const isSensor = source.domain === 'SENSORS';

  return (
    <DrawerPanel
      isOpen={isOpen}
      onClose={onClose}
      title={`Configure: ${source.name}`}
      subtitle={`Source ID: ${source.id} (${source.domain.replace('_', ' / ')})`}
      width="max-w-2xl"
    >
      <div className="space-y-5 font-mono text-xs">
        {/* Toggle Status Card */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 text-sm">Source Ingestion Status</span>
              <span
                className={`text-[10px] px-2 py-0.2 rounded font-bold ${
                  source.enabled
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {source.enabled ? 'ACTIVE' : 'DISABLED'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              {source.enabled
                ? 'Ingesting new records and contributing to correlation passes.'
                : 'Excluded from new ingestion and correlation passes. Historical data preserved.'}
            </p>
          </div>
          <Toggle
            checked={source.enabled}
            onChange={() => onToggle(source.domain, source.id)}
            size="md"
          />
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 border-b border-slate-800 pb-1">
          {[
            { id: 'general', label: 'General' },
            { id: 'network', label: 'Network / API' },
            { id: 'ingestion', label: isSatellite ? 'Telemetry Settings' : 'Ingestion Pipeline' },
            { id: 'mapping', label: 'Field Normalization' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-t transition-colors ${
                activeTab === tab.id
                  ? 'bg-slate-800 text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
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
              <label className="block text-slate-400 text-[11px] uppercase mb-1">Source Name</label>
              <input
                type="text"
                defaultValue={source.name}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 text-[11px] uppercase mb-1">Description</label>
              <textarea
                rows={2}
                defaultValue={source.description}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-400 text-[11px] uppercase mb-1">Operational Domain</label>
                <input
                  type="text"
                  disabled
                  value={source.domain}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-400 opacity-80"
                />
              </div>
              <div>
                <label className="block text-slate-400 text-[11px] uppercase mb-1">Source Adapter</label>
                <input
                  type="text"
                  disabled
                  value={`${source.sourceType}Adapter`}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-400 opacity-80"
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Network / API */}
        {activeTab === 'network' && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block text-slate-400 text-[11px] uppercase mb-1">Host / IP / Endpoint</label>
                <input
                  type="text"
                  defaultValue={source.connectionHost || 'api.telemetry.domain.local'}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 text-[11px] uppercase mb-1">Port</label>
                <input
                  type="number"
                  defaultValue={source.connectionPort || 443}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-400 text-[11px] uppercase mb-1">Protocol</label>
                <select
                  defaultValue={source.protocol || 'HTTPS'}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option>HTTPS</option>
                  <option>TCP/TLS</option>
                  <option>IPFIX/NetFlow</option>
                  <option>Syslog/TLS</option>
                  <option>REST/JSON</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-400 text-[11px] uppercase mb-1">Authentication</label>
                <select className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500">
                  <option>API Token / Bearer</option>
                  <option>Mutual TLS (mTLS)</option>
                  <option>Basic Auth</option>
                  <option>None (Direct Socket)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-slate-400 text-[11px] uppercase mb-1">API Key / Token</label>
              <input
                type="password"
                defaultValue="sk-soc-telemetry-demo-token-988472"
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-400 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Test Connection Button & Status */}
            <div className="pt-2">
              <button
                onClick={handleTestConnection}
                disabled={testingConnection || !source.enabled}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 font-bold rounded flex items-center gap-2 border border-slate-700 transition-colors cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${testingConnection ? 'animate-spin text-cyan-400' : ''}`} />
                Test Connection Handshake
              </button>

              {testResult && (
                <div className="mt-3 p-3 bg-emerald-950/40 border border-emerald-800 rounded text-emerald-300 flex items-start gap-2">
                  <Check className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">{testResult.message}</span>
                    <span className="block text-[10px] text-emerald-400/80 mt-0.5">
                      Roundtrip Latency: {testResult.latencyMs} ms
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: Ingestion / Telemetry Settings */}
        {activeTab === 'ingestion' && (
          <div className="space-y-4">
            {isSiem && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Ingestion Format</label>
                    <select className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200">
                      <option>JSON (Mordor / Sysmon)</option>
                      <option>EVTX (Windows Event XML)</option>
                      <option>CSV (CIC-CSE-IDS2018)</option>
                      <option>ET-Open Suricata Fast Log</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Polling Interval</label>
                    <input
                      type="text"
                      defaultValue="30 seconds"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Batch Size</label>
                    <input
                      type="number"
                      defaultValue={500}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Max Events / Cycle</label>
                    <input
                      type="number"
                      defaultValue={10000}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
              </>
            )}

            {isSatellite && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Telemetry Channel</label>
                    <input
                      type="text"
                      defaultValue="P-1 (Radiation / Spectrometer)"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Sampling Interval</label>
                    <input
                      type="text"
                      defaultValue="5 seconds"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Baseline Window</label>
                    <input
                      type="text"
                      defaultValue="100 telemetry frames"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Anomaly Threshold</label>
                    <input
                      type="text"
                      defaultValue="2.5 σ (Standard Deviation)"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
                <div className="p-3 bg-amber-950/30 border border-amber-900/50 rounded text-amber-300 text-xs">
                  <strong>Telemetry Safety Principle:</strong> Anomaly detection generates initial
                  classification as "Telemetry Anomaly". It will not be marked as a confirmed cyber attack
                  without corroborating cyber telemetry.
                </div>
              </>
            )}

            {isSensor && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Sensor Type</label>
                    <select className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200">
                      <option>Network Sensor (IPFIX/NetFlow)</option>
                      <option>Endpoint Sensor (Process / EDR)</option>
                      <option>Facility Sensor (Modbus/SCADA)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Asset Scope</label>
                    <input
                      type="text"
                      defaultValue="SERVER-07, DC-01, WORKSTATION-14"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Sampling Rate</label>
                    <input
                      type="text"
                      defaultValue="1000 events/sec"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 text-[11px] uppercase mb-1">Batch Buffer</label>
                    <input
                      type="text"
                      defaultValue="10 MB"
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
                    />
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* TAB 4: Field Normalization Mapping */}
        {activeTab === 'mapping' && (
          <div className="space-y-3">
            <div className="text-slate-400 text-xs">
              Configured Source Adapter field extractions to Sparse Canonical Event:
            </div>
            <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-2">
              {[
                { src: '@timestamp / TimeCreated', canonical: 'timestamp' },
                { src: 'source_ip / Source IP', canonical: 'indicators[]' },
                { src: 'destination_ip / Destination IP', canonical: 'indicators[]' },
                { src: 'hostname / Computer / spacecraft', canonical: 'asset' },
                { src: 'event_type / Label / Channel', canonical: 'eventType' },
                { src: 'severity / Level', canonical: 'sourceSeverity' },
              ].map((m, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between py-1 px-2 rounded bg-slate-900/60 border border-slate-800 text-[11px]"
                >
                  <span className="text-slate-300 font-bold">{m.src}</span>
                  <span className="text-cyan-400 font-bold">→</span>
                  <span className="text-cyan-300 font-bold">{m.canonical}</span>
                </div>
              ))}
            </div>
            <p className="text-[10px] text-slate-500">
              Unmatched fields remain in raw provenance; canonical event stores sparse payload.
            </p>
          </div>
        )}
      </div>
    </DrawerPanel>
  );
};
