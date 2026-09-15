import React, { useState } from 'react';
import { mockNormalizationRecords } from '../../data/mockNormalization';
import { Card } from '../../components/ui/Card';
import { MissingField } from '../../components/ui/MissingField';
import { ConfidenceMeter } from '../../components/ui/ConfidenceMeter';
import {
  ArrowRight,
  GitBranch,
  Layers,
  Database,
  Code,
  CheckCircle2,
  AlertCircle,
  FileSpreadsheet,
} from 'lucide-react';

export const NormalizationPage: React.FC = () => {
  const [selectedRecordIndex, setSelectedRecordIndex] = useState<number>(0);
  const selectedRecord = mockNormalizationRecords[selectedRecordIndex];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          HETEROGENEOUS DATA NORMALIZATION PIPELINE
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          Visualizing how disparate SIEM, Space Telemetry, and Sensor records transform into sparse canonical events
        </p>
      </div>

      {/* Visual Pipeline Flow Banner */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-sm p-5 shadow-lg">
        <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-4 font-bold flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-cyan-400" />
          Canonical Event Extraction Pipeline
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 font-mono text-xs text-center">
          <div className="p-3 bg-slate-900 border border-slate-800 rounded">
            <span className="text-[10px] text-slate-500 uppercase block">Step 1</span>
            <strong className="text-slate-200 mt-1 block">RAW SOURCE</strong>
            <span className="text-[10px] text-slate-400 mt-0.5 block">JSON / EVTX / CSV</span>
          </div>

          <div className="flex items-center justify-center text-slate-600 hidden md:flex">
            <ArrowRight className="w-5 h-5 text-cyan-500" />
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800 rounded">
            <span className="text-[10px] text-slate-500 uppercase block">Step 2</span>
            <strong className="text-cyan-300 mt-1 block">SOURCE ADAPTER</strong>
            <span className="text-[10px] text-slate-400 mt-0.5 block">Domain Parser</span>
          </div>

          <div className="flex items-center justify-center text-slate-600 hidden md:flex">
            <ArrowRight className="w-5 h-5 text-cyan-500" />
          </div>

          <div className="p-3 bg-cyan-950/40 border border-cyan-700/60 rounded">
            <span className="text-[10px] text-cyan-400 uppercase block font-bold">Step 3</span>
            <strong className="text-cyan-200 mt-1 block">SPARSE CANONICAL EVENT</strong>
            <span className="text-[10px] text-cyan-300 mt-0.5 block">Preserves Provenance URI</span>
          </div>
        </div>
      </div>

      {/* Source Selector Bar */}
      <div className="flex flex-wrap items-center gap-2 bg-slate-900/80 p-2 rounded border border-slate-800 font-mono text-xs">
        <span className="text-slate-400 px-2 text-[11px] uppercase font-bold">Inspect Adapter:</span>
        {mockNormalizationRecords.map((rec, idx) => (
          <button
            key={rec.sourceId}
            onClick={() => setSelectedRecordIndex(idx)}
            className={`px-3 py-1.5 rounded transition-colors font-semibold cursor-pointer ${
              selectedRecordIndex === idx
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {rec.sourceName} ({rec.domain.replace('_', ' / ')})
          </button>
        ))}
      </div>

      {/* Side-by-Side: Raw Record vs Canonical Event & Completeness */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Raw Source Payload */}
        <div className="lg:col-span-5">
          <Card
            title={`Raw Record: ${selectedRecord.sourceName}`}
            subtitle={`Ingested via ${selectedRecord.adapterName}`}
          >
            <div className="space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between text-[11px] text-slate-400 border-b border-slate-800 pb-2">
                <span>Original Schema Format:</span>
                <span className="text-slate-200 font-bold uppercase">
                  {selectedRecord.sourceId === 'mordor'
                    ? 'JSON / Sysmon'
                    : selectedRecord.sourceId === 'evtx'
                    ? 'XML Event Log'
                    : selectedRecord.sourceId === 'cic_ids'
                    ? 'CSV NetFlow'
                    : selectedRecord.sourceId === 'nasa_telemanom'
                    ? 'Telemetry Frame'
                    : 'Endpoint Telemetry'}
                </span>
              </div>

              <pre className="p-3 bg-slate-950 text-slate-300 rounded border border-slate-800 text-[11px] overflow-x-auto leading-relaxed max-h-96">
                {JSON.stringify(selectedRecord.rawSample, null, 2)}
              </pre>

              <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800 text-[11px] text-slate-400">
                💡 <strong>Pipeline Principle:</strong> This raw payload is archived in hot storage.
                Only extracted sparse fields pass downstream to avoid saturating correlation memory.
              </div>
            </div>
          </Card>
        </div>

        {/* Right: Sparse Canonical Model & Field Presence */}
        <div className="lg:col-span-7">
          <Card
            title="Sparse Canonical Representation"
            subtitle="Normalized Event with Verified Non-Fabricated Fields"
            badge={
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                {selectedRecord.dataCompleteness}% Completeness
              </span>
            }
          >
            <div className="space-y-4 font-mono text-xs">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded">
                <ConfidenceMeter
                  value={selectedRecord.dataCompleteness}
                  label="Data Completeness Score"
                  type="completeness"
                  showPercent
                />
                <p className="text-[10px] text-slate-500 mt-1 italic">
                  Note: Data completeness reflects field availability from this specific source type.
                  Missing fields are never fabricated or penalized as malicious.
                </p>
              </div>

              {/* Field mapping table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 text-[10px] uppercase tracking-wider">
                      <th className="py-2 px-3">Canonical Field</th>
                      <th className="py-2 px-3">Source Field</th>
                      <th className="py-2 px-3">Extracted Value</th>
                      <th className="py-2 px-3 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {selectedRecord.fields.map((field, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30">
                        <td className="py-2 px-3 font-bold text-slate-200">
                          {field.canonicalField}
                        </td>
                        <td className="py-2 px-3 text-slate-400">
                          {field.sourceField}
                        </td>
                        <td className="py-2 px-3">
                          {field.present ? (
                            <span className="text-cyan-300 font-bold">{field.value}</span>
                          ) : (
                            <MissingField />
                          )}
                        </td>
                        <td className="py-2 px-3 text-right">
                          {field.present ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Extracted
                            </span>
                          ) : (
                            <span className="text-[10px] text-slate-500 italic">
                              — Not provided
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="p-3 bg-cyan-950/20 border border-cyan-900/40 rounded text-slate-300 text-xs flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Semantic Model Rule:</strong> Canonical events are sparse by design. A Windows
                  EVTX log contains PowerShell commands but no IP address; a NetFlow record contains
                  IPs and ports but no process names. Normalization accommodates both without data distortion.
                </span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
