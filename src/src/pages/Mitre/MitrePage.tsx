import React, { useState } from 'react';
import { Crosshair, ChevronDown, ChevronRight, RefreshCw, Wifi, WifiOff } from 'lucide-react';
import { Card } from '../../components/ui/Card';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { MitreMappingResult } from '../../types';
import { useSentinel } from '../../store/sentinelStore';

// ---------------------------------------------------------------------------
// Confidence badge helper
// ---------------------------------------------------------------------------
type ConfidenceLevel = 'high' | 'med' | 'low';

function confidenceLevel(score: number): ConfidenceLevel {
  if (score >= 75) return 'high';
  if (score >= 45) return 'med';
  return 'low';
}

const CONFIDENCE_STYLES: Record<ConfidenceLevel, string> = {
  high: 'bg-emerald-950 text-emerald-300 border border-emerald-700',
  med:  'bg-amber-950  text-amber-300  border border-amber-700',
  low:  'bg-red-950    text-red-300    border border-red-700',
};

const CONFIDENCE_LABELS: Record<ConfidenceLevel, string> = {
  high: 'HIGH',
  med:  'MED',
  low:  'LOW',
};

function ConfidenceBadge({ score }: { score: number }) {
  const level = confidenceLevel(score);
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono ${CONFIDENCE_STYLES[level]}`}>
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          level === 'high' ? 'bg-emerald-400' : level === 'med' ? 'bg-amber-400' : 'bg-red-400'
        }`}
      />
      {CONFIDENCE_LABELS[level]} — {score}%
    </span>
  );
}

// ---------------------------------------------------------------------------
// Tactic category badge
// ---------------------------------------------------------------------------
const TACTIC_COLORS: Record<string, string> = {
  'Initial Access':       'bg-purple-950 text-purple-300 border-purple-700',
  'Execution':            'bg-blue-950   text-blue-300   border-blue-700',
  'Persistence':          'bg-indigo-950 text-indigo-300 border-indigo-700',
  'Privilege Escalation': 'bg-orange-950 text-orange-300 border-orange-700',
  'Defense Evasion':      'bg-slate-800  text-slate-300  border-slate-600',
  'Credential Access':    'bg-rose-950   text-rose-300   border-rose-700',
  'Discovery':            'bg-teal-950   text-teal-300   border-teal-700',
  'Lateral Movement':     'bg-cyan-950   text-cyan-300   border-cyan-700',
  'Collection':           'bg-yellow-950 text-yellow-300 border-yellow-700',
  'Command and Control':  'bg-violet-950 text-violet-300 border-violet-700',
  'Exfiltration':         'bg-pink-950   text-pink-300   border-pink-700',
  'Impact':               'bg-red-950    text-red-300    border-red-700',
};

function TacticBadge({ tactic }: { tactic: string }) {
  const cls = TACTIC_COLORS[tactic] ?? 'bg-slate-800 text-slate-300 border-slate-600';
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${cls}`}>
      {tactic}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Expandable evidence row
// ---------------------------------------------------------------------------
function EvidenceDrawer({ evidence }: { evidence: string[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
        className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-cyan-300 font-mono transition-colors"
      >
        {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        {evidence.length} evidence item{evidence.length !== 1 ? 's' : ''}
      </button>
      {open && (
        <ul className="mt-1.5 space-y-1 pl-3 border-l border-slate-700">
          {evidence.map((ev, i) => (
            <li key={i} className="text-[10px] text-slate-300 font-mono leading-relaxed">
              {ev}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

// Default cluster payloads wired to the known incidents/alerts in the store.
// Replace / extend these to match real incident IDs from the correlation engine.
const DEFAULT_CLUSTER_PAYLOADS = [
  {
    cluster_id: 'INC-0042',
    summary: 'Lateral movement detected via RDP from compromised workstation. Followed by PowerShell encoded commands on domain controller.',
    alert_titles: ['RDP Login from Unusual Source', 'Suspicious PowerShell Encoded Command'],
    indicators: ['192.168.12.44', 'dc01.corp.local'],
    tactic_hint: 'Lateral Movement',
  },
  {
    cluster_id: 'INC-0039',
    summary: 'Multiple failed login attempts across ten service accounts within five minutes. Consistent with password spraying pattern.',
    alert_titles: ['Failed Login – Multiple Accounts', 'Account Lockout Threshold Breached'],
    indicators: ['svc_backup', 'svc_monitor', 'admin'],
    tactic_hint: 'Credential Access',
  },
  {
    cluster_id: 'INC-0035',
    summary: 'Unusual outbound HTTPS traffic to known C2 infrastructure. High-volume data transfer observed post-compromise.',
    alert_titles: ['Suspicious Outbound HTTPS Volume', 'Known C2 Domain Contacted'],
    indicators: ['185.234.219.45', 'update-cdn.net'],
    tactic_hint: 'Command and Control',
  },
];

export const MitrePage: React.FC = () => {
  const { mitreMappings, mitreMappingLoading, mitreMappingError, runMitreMapping } = useSentinel();
  const [selectedMapping, setSelectedMapping] = useState<MitreMappingResult | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  const handleRunMapping = async () => {
    // Attempt a health-check first so we can show the connectivity badge
    try {
      const resp = await fetch('http://localhost:8000/api/mitre/health', {
        signal: AbortSignal.timeout(4000),
      });
      setBackendOnline(resp.ok);
    } catch {
      setBackendOnline(false);
    }
    await runMitreMapping(DEFAULT_CLUSTER_PAYLOADS);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
            MITRE ATT&CK CONTEXTUAL ENRICHMENT
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            RAG-mapped adversary behaviors from correlated incident clusters — Enterprise Matrix v15
          </p>
        </div>

        {/* Run mapping / status controls */}
        <div className="flex items-center gap-3">
          {backendOnline !== null && (
            <span className={`flex items-center gap-1.5 text-[10px] font-mono ${backendOnline ? 'text-emerald-400' : 'text-amber-400'}`}>
              {backendOnline
                ? <><Wifi className="w-3 h-3" /> Backend online</>
                : <><WifiOff className="w-3 h-3" /> Using mock data</>
              }
            </span>
          )}
          <button
            onClick={handleRunMapping}
            disabled={mitreMappingLoading}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono font-semibold rounded border border-cyan-700 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 disabled:opacity-50 disabled:cursor-wait transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${mitreMappingLoading ? 'animate-spin' : ''}`} />
            {mitreMappingLoading ? 'Mapping…' : 'Run RAG Mapping'}
          </button>
        </div>
      </div>

      {/* Scope notice */}
      <div className="bg-slate-900/80 border border-slate-800 rounded p-3 text-xs font-mono text-slate-400 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-cyan-400" />
          <span>
            <strong className="text-slate-200">Focused Contextual Scope:</strong> Displaying{' '}
            <span className="text-cyan-400 font-bold">{mitreMappings.length} technique{mitreMappings.length !== 1 ? 's' : ''}</span>{' '}
            mapped to observed telemetry via watsonx.ai RAG pipeline.
          </span>
        </div>
        <span className="text-[11px] text-slate-400">Enterprise Matrix v15</span>
      </div>

      {/* Error banner */}
      {mitreMappingError && (
        <div className="bg-red-950/40 border border-red-800 rounded p-3 text-xs font-mono text-red-300">
          <strong>Mapping error:</strong> {mitreMappingError}
        </div>
      )}

      {/* Techniques Table */}
      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/70 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Technique ID</th>
                <th className="py-3 px-4">Technique Name</th>
                <th className="py-3 px-4">Tactic</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {mitreMappings.map((mapping, idx) => (
                <tr
                  key={`${mapping.technique_id}-${idx}`}
                  onClick={() => setSelectedMapping(mapping)}
                  className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                >
                  {/* Technique ID */}
                  <td className="py-3 px-4 font-bold text-cyan-400">
                    <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      {mapping.technique_id}
                    </span>
                  </td>

                  {/* Name */}
                  <td className="py-3 px-4 text-slate-100 font-semibold">
                    {mapping.technique_name}
                  </td>

                  {/* Tactic */}
                  <td className="py-3 px-4">
                    <TacticBadge tactic={mapping.tactic} />
                  </td>

                  {/* Confidence badge */}
                  <td className="py-3 px-4">
                    <ConfidenceBadge score={mapping.confidence_score} />
                  </td>

                  {/* Evidence inline expander */}
                  <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                    <EvidenceDrawer evidence={mapping.evidence} />
                  </td>
                </tr>
              ))}

              {mitreMappings.length === 0 && !mitreMappingLoading && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No mappings yet — click "Run RAG Mapping" to query the backend.
                  </td>
                </tr>
              )}

              {mitreMappingLoading && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-cyan-400 font-mono text-xs animate-pulse">
                    Running RAG pipeline…
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Technique detail drawer */}
      <DrawerPanel
        isOpen={!!selectedMapping}
        onClose={() => setSelectedMapping(null)}
        title={selectedMapping ? `${selectedMapping.technique_id}: ${selectedMapping.technique_name}` : ''}
        subtitle={selectedMapping?.tactic}
      >
        {selectedMapping && (
          <div className="space-y-4 font-mono text-xs">
            {/* Confidence + Tactic grid */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase block mb-1">Attribution Confidence</span>
                <ConfidenceBadge score={selectedMapping.confidence_score} />
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase block mb-1">Tactic Category</span>
                <TacticBadge tactic={selectedMapping.tactic} />
              </div>
            </div>

            {/* Technique link */}
            <div className="p-3 bg-slate-900 border border-slate-800 rounded flex items-center justify-between">
              <span className="text-slate-400 text-[10px] uppercase">ATT&CK Reference</span>
              <a
                href={`https://attack.mitre.org/techniques/${selectedMapping.technique_id.replace('.', '/')}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:underline text-[10px]"
              >
                attack.mitre.org ↗
              </a>
            </div>

            {/* Evidence list */}
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 text-[10px] uppercase block mb-2">
                Supporting Evidence ({selectedMapping.evidence.length})
              </span>
              <ul className="space-y-1.5">
                {selectedMapping.evidence.map((ev, i) => (
                  <li key={i} className="flex items-start gap-2 text-slate-300 text-xs leading-relaxed">
                    <span className="text-cyan-500 mt-0.5">›</span>
                    {ev}
                  </li>
                ))}
              </ul>
            </div>

            {/* Confidence legend */}
            <div className="p-3 bg-slate-900/50 border border-slate-800 rounded">
              <span className="text-slate-400 text-[10px] uppercase block mb-2">Confidence Legend</span>
              <div className="flex gap-3">
                <ConfidenceBadge score={80} />
                <ConfidenceBadge score={60} />
                <ConfidenceBadge score={30} />
              </div>
              <p className="text-slate-500 text-[10px] mt-2 leading-relaxed">
                Score is a blend of vector-similarity distance and watsonx.ai LLM re-ranking confidence.
                High ≥ 75 · Med 45–74 · Low &lt; 45
              </p>
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
