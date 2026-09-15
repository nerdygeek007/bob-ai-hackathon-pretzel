import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { mockBLUFReports } from '../../data/mockNormalization';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import {
  FileText,
  Download,
  RefreshCw,
  Printer,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
} from 'lucide-react';

export const BLUFPage: React.FC = () => {
  const { incidents, selectedIncidentId, setSelectedIncidentId } = useSentinel();
  const [isGenerating, setIsGenerating] = useState(false);
  const [exportedNotice, setExportedNotice] = useState(false);

  const report =
    mockBLUFReports.find((r) => r.incidentId === selectedIncidentId) || mockBLUFReports[0];

  const handleRegenerate = () => {
    setIsGenerating(true);
    setTimeout(() => {
      setIsGenerating(false);
    }, 600);
  };

  const handleExport = () => {
    setExportedNotice(true);
    setTimeout(() => setExportedNotice(false), 3000);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
            COMMANDER BLUF EXECUTIVE BRIEFINGS
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Bottom Line Up Front — mission impact, corroborating evidence, and operational response actions
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRegenerate}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin text-cyan-400' : ''}`} />
            Regenerate
          </button>

          <button
            onClick={handleExport}
            className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold flex items-center gap-1.5 shadow-md shadow-cyan-950 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Briefing
          </button>
        </div>
      </div>

      {exportedNotice && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800 rounded text-emerald-300 font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>Executive Briefing exported as encrypted PDF artifact to SOC document repository.</span>
        </div>
      )}

      {/* Incident Switcher */}
      <div className="flex flex-wrap items-center gap-2 bg-slate-900/80 p-2 rounded border border-slate-800 font-mono text-xs">
        <span className="text-slate-400 font-bold uppercase text-[11px]">Select Incident Dossier:</span>
        {incidents.map((inc) => (
          <button
            key={inc.incidentId}
            onClick={() => setSelectedIncidentId(inc.incidentId)}
            className={`px-3 py-1.5 rounded transition-colors font-semibold cursor-pointer ${
              inc.incidentId === selectedIncidentId
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {inc.incidentId} ({inc.priority})
          </button>
        ))}
      </div>

      {/* COMMANDER BLUF DOSSIER SHEET */}
      <div className="bg-[#111827] border-2 border-[#1f293d] rounded-sm p-7 shadow-2xl space-y-6 font-mono max-w-4xl mx-auto">
        {/* Dossier Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b-2 border-slate-800">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-xs px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold tracking-widest uppercase">
                EXECUTIVE BRIEFING
              </span>
              <span className="text-xs text-slate-500">SENTINEL-X AI ASSISTANT</span>
            </div>
            <h2 className="text-2xl font-black text-slate-100 uppercase tracking-wide mt-1">
              COMMANDER BLUF: {report.incidentId}
            </h2>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              Generated: {new Date(report.generatedAt).toUTCString()}
            </span>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <span className="text-[10px] text-slate-400 uppercase tracking-widest block font-bold">
                Assigned Priority
              </span>
              <div className="mt-1">
                <SeverityBadge severity={report.priority} size="lg" variant="sentinel" />
              </div>
            </div>
          </div>
        </div>

        {/* 1. BOTTOM LINE */}
        <div className="p-4 bg-slate-900/90 border-l-4 border-cyan-400 rounded-r">
          <span className="text-[11px] text-cyan-400 uppercase font-black tracking-widest block mb-1">
            BOTTOM LINE
          </span>
          <p className="text-sm font-semibold text-slate-100 leading-relaxed">
            "{report.bottomLine}"
          </p>
        </div>

        {/* 2. WHY IT MATTERS */}
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-bold tracking-wider block mb-1.5">
            WHY IT MATTERS
          </span>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/40 p-3 rounded border border-slate-800/80">
            {report.whyItMatters}
          </p>
        </div>

        {/* 3. METRICS STRIP: RISK & CONFIDENCE */}
        <div className="grid grid-cols-2 gap-4 py-2 border-y border-slate-800">
          <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400 uppercase font-semibold">Calculated Risk:</span>
            <span className="text-lg font-black text-red-400">{report.riskScore} / 100</span>
          </div>

          <div className="p-3 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400 uppercase font-semibold">Assessment Confidence:</span>
            <span className="text-lg font-black text-cyan-400">{report.confidence}%</span>
          </div>
        </div>

        {/* 4. CORROBORATING EVIDENCE */}
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-bold tracking-wider block mb-2">
            CORROBORATING EVIDENCE SUMMARY
          </span>
          <ul className="space-y-1.5">
            {report.evidenceSummary.map((ev, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2 text-xs text-slate-300 p-2 rounded bg-slate-900/50 border border-slate-800"
              >
                <span className="text-cyan-400 font-bold">•</span>
                <span>{ev}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* 5. MITRE ATT&CK BEHAVIORS */}
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-bold tracking-wider block mb-2">
            RELEVANT MITRE ATT&CK TECHNIQUES
          </span>
          <div className="flex flex-wrap gap-2">
            {report.mitreIds.map((tid) => (
              <span
                key={tid}
                className="px-2.5 py-1 rounded text-xs bg-cyan-950/80 text-cyan-300 border border-cyan-700 font-bold"
              >
                {tid}
              </span>
            ))}
          </div>
        </div>

        {/* 6. RECOMMENDED ACTIONS */}
        <div>
          <span className="text-[11px] text-emerald-400 uppercase font-bold tracking-wider block mb-2">
            COMMANDER RECOMMENDED RESPONSE ACTIONS
          </span>
          <ol className="space-y-2">
            {report.recommendedActions.map((action, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2.5 text-xs text-slate-200 p-2.5 rounded bg-slate-900/80 border border-emerald-950/60"
              >
                <span className="w-5 h-5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-700 font-bold text-[10px] flex items-center justify-center shrink-0">
                  {idx + 1}
                </span>
                <span className="mt-0.5">{action}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Classification footer */}
        <div className="pt-4 border-t border-slate-800 text-center text-[10px] text-slate-500">
          {report.classificationNote}
        </div>
      </div>
    </div>
  );
};
