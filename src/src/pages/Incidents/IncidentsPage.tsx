import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { Incident } from '../../types';
import {
  ArrowRight,
  ShieldAlert,
  Radio,
  Clock,
  Layers,
  ChevronRight,
  AlertTriangle,
} from 'lucide-react';

export const IncidentsPage: React.FC = () => {
  const navigate = useNavigate();
  const { incidents, setSelectedIncidentId } = useSentinel();

  const handleOpenDetail = (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    navigate(`/incidents/${incidentId}`);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#171717]">
            Correlated Incidents
          </h1>
          <p className="text-sm text-[#737373] mt-0.5">
            Multi-stage attack chains correlated across independent security domains
          </p>
        </div>
        <div className="text-xs text-[#737373]">
          <span className="font-medium text-[#171717]">{incidents.length}</span> active incidents under observation
        </div>
      </div>

      {/* Incidents List (Clean Cards, not overwhelming charts) */}
      <div className="space-y-4">
        {incidents.map((inc) => {
          const isSatelliteAnomaly = inc.incidentId === 'INC-1043';

          return (
            <div
              key={inc.incidentId}
              onClick={() => handleOpenDetail(inc.incidentId)}
              className="bg-white border border-[#e5e5e5] hover:border-neutral-300 rounded-xl p-5 shadow-[0_1px_2px_rgba(0,0,0,0.03)] transition-all cursor-pointer group"
            >
              {/* Header row: ID, Title, Status, Priority, Risk Score */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[#e5e5e5]">
                <div className="flex items-start gap-3.5">
                  <div className="p-2.5 rounded-xl bg-[#f5f5f5] text-[#171717] shrink-0 border border-[#e5e5e5]">
                    {isSatelliteAnomaly ? (
                      <Radio className="w-5 h-5 text-blue-600" />
                    ) : (
                      <Layers className="w-5 h-5 text-blue-600" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-bold text-xs text-[#171717] bg-[#f5f5f5] px-2 py-0.5 rounded-md border border-[#e5e5e5]">
                        {inc.incidentId}
                      </span>
                      <h2 className="text-base font-bold text-[#171717] group-hover:text-blue-600 transition-colors">
                        {inc.title}
                      </h2>
                      <SeverityBadge severity={inc.priority} size="sm" variant="sentinel" />
                      <span className="text-[11px] px-2 py-0.5 rounded-full bg-[#f5f5f5] text-[#737373] border border-[#e5e5e5]">
                        {inc.status}
                      </span>
                    </div>

                    {/* Metadata line: Target assets & related telemetry */}
                    <div className="flex items-center gap-3 text-xs text-[#737373] mt-1.5 flex-wrap">
                      <span>
                        Asset: <strong className="text-[#171717] font-mono">{inc.affectedAsset}</strong>
                        {inc.affectedAssets && inc.affectedAssets.length > 1 && (
                          <span className="text-[#737373]"> (+{inc.affectedAssets.length - 1} secondary)</span>
                        )}
                      </span>
                      <span>•</span>
                      <span>{inc.correlatedAlertIds.length} related alerts</span>
                      <span>•</span>
                      <span>{inc.mitreIds.length} MITRE techniques</span>
                      <span>•</span>
                      <span>Confidence: <strong className="text-[#171717] font-mono">{inc.confidence}%</strong></span>
                    </div>
                  </div>
                </div>

                {/* Right: Risk Score & Action */}
                <div className="flex items-center gap-4 self-end lg:self-center">
                  <div className="text-right">
                    <span className="text-[10px] uppercase font-medium tracking-wider text-[#737373] block">
                      Assessed Risk
                    </span>
                    <div className="flex items-baseline gap-1 font-mono">
                      <span className="text-xl font-bold text-[#171717]">{inc.riskScore}</span>
                      <span className="text-xs text-[#737373]">/ 100</span>
                    </div>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOpenDetail(inc.incidentId);
                    }}
                    className="px-3.5 py-1.5 rounded-lg bg-[#000000] text-white hover:bg-neutral-800 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    View Details <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Summary description */}
              <p className="text-xs text-[#737373] my-3 leading-relaxed">
                {inc.blufSummary}
              </p>

              {/* Attack Stage Timeline (Section 14) */}
              {inc.timeline && inc.timeline.length > 0 && (
                <div className="pt-3 border-t border-[#e5e5e5]">
                  <span className="text-[11px] font-semibold text-[#737373] uppercase tracking-wider block mb-2">
                    Attack Progression Timeline
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                    {inc.timeline.map((step, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] text-xs flex flex-col justify-between"
                      >
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className="font-mono text-xs font-bold text-[#171717]">
                            {step.time}
                          </span>
                          {step.mitre && (
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-white text-[#737373] border border-[#e5e5e5]">
                              {step.mitre}
                            </span>
                          )}
                        </div>
                        <span className="font-medium text-[#171717] block">
                          {step.stage}
                        </span>
                        <span className="text-[11px] text-[#737373] mt-1 line-clamp-2">
                          {step.description}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
