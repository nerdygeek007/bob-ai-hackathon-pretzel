import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { RiskGauge } from '../../components/ui/RiskGauge';
import { ConfidenceMeter } from '../../components/ui/ConfidenceMeter';
import { Incident } from '../../types';
import { ShieldCheck, ShieldAlert, AlertTriangle, ArrowRight, Layers, FileText } from 'lucide-react';

export const IncidentsPage: React.FC = () => {
  const navigate = useNavigate();
  const { incidents, setSelectedIncidentId } = useSentinel();

  const handleOpenDetail = (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    navigate(`/incidents/${incidentId}`);
  };

  const getAssessmentBadge = (inc: Incident) => {
    if (inc.threatAssessment === 'LIKELY_THREAT') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-red-950/80 text-red-400 border border-red-800">
          <ShieldAlert className="w-3.5 h-3.5" /> LIKELY THREAT
        </span>
      );
    }
    if (inc.threatAssessment === 'LIKELY_FALSE_POSITIVE') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
          <ShieldCheck className="w-3.5 h-3.5" /> LIKELY FALSE POSITIVE
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800">
        <AlertTriangle className="w-3.5 h-3.5" /> REQUIRES INVESTIGATION
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
            CORRELATED INCIDENTS
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Explainable multi-source incident clusters with false positive triage and risk attribution
          </p>
        </div>
      </div>

      {/* Incidents Grid */}
      <div className="grid grid-cols-1 gap-5">
        {incidents.map((inc) => (
          <div
            key={inc.incidentId}
            className="bg-[#111827] border border-[#1f293d] hover:border-slate-600 rounded-sm p-5 shadow-lg transition-all duration-200"
          >
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-4 border-b border-[#1f293d]">
              {/* Left meta */}
              <div className="flex items-start gap-4">
                <RiskGauge score={inc.riskScore} size={84} />
                <div>
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-base font-black font-mono text-cyan-400">
                      {inc.incidentId}
                    </span>
                    <SeverityBadge severity={inc.priority} size="md" variant="sentinel" />
                    {getAssessmentBadge(inc)}
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      Status: {inc.status}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-slate-200 mt-2 font-mono">
                    Target Asset:{' '}
                    <span className="text-slate-100 font-bold bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                      {inc.affectedAsset}
                    </span>
                  </h3>

                  <p className="text-xs text-slate-400 mt-1 max-w-2xl line-clamp-2">
                    {inc.blufSummary}
                  </p>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex items-center gap-3 self-end lg:self-center">
                <button
                  onClick={() => {
                    setSelectedIncidentId(inc.incidentId);
                    navigate('/bluf');
                  }}
                  className="px-3 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  BLUF Report
                </button>

                <button
                  onClick={() => handleOpenDetail(inc.incidentId)}
                  className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold flex items-center gap-1.5 transition-colors cursor-pointer shadow-md shadow-cyan-950"
                >
                  Investigate Incident <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Bottom details strip */}
            <div className="pt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
              {/* Evidence Domains */}
              <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">
                  Evidence Streams ({inc.evidenceDomains.length})
                </span>
                <div className="flex flex-wrap gap-1">
                  {inc.evidenceDomains.map((dom) => (
                    <span
                      key={dom}
                      className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-bold"
                    >
                      {dom.replace('_', ' / ')}
                    </span>
                  ))}
                </div>
              </div>

              {/* Correlated Alerts count */}
              <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">
                  Correlated Alerts
                </span>
                <span className="font-bold text-slate-200 flex items-center gap-1">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  {inc.correlatedAlertIds.length} telemetry records
                </span>
              </div>

              {/* Confidence & Completeness (Separated) */}
              <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800 space-y-1.5">
                <ConfidenceMeter value={inc.confidence} label="Assessment Confidence" size="sm" />
                <ConfidenceMeter
                  value={inc.dataCompleteness}
                  label="Data Completeness"
                  type="completeness"
                  size="sm"
                />
              </div>

              {/* MITRE Mapping */}
              <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">
                  MITRE ATT&CK ({inc.mitreIds.length})
                </span>
                <div className="flex flex-wrap gap-1">
                  {inc.mitreIds.map((tid) => (
                    <span
                      key={tid}
                      className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-950/60 text-cyan-400 border border-cyan-800 font-semibold"
                    >
                      {tid}
                    </span>
                  ))}
                  {inc.cveIds?.map((cve) => (
                    <span
                      key={cve}
                      className="px-1.5 py-0.5 rounded text-[10px] bg-red-950/60 text-red-400 border border-red-800 font-semibold"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
