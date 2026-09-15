import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { Alert, PriorityLevel } from '../../types';
import {
  Search,
  ArrowUpRight,
  ExternalLink,
  Shield,
  Clock,
  CheckCircle,
  AlertTriangle,
  Layers,
  ChevronRight,
} from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const { alerts, updateAlertStatus } = useSentinel();
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredAlerts = alerts.filter((alert) => {
    // Priority filter
    if (priorityFilter !== 'ALL') {
      const alertPriority = alert.priority || alert.sourceSeverity;
      if (alertPriority !== priorityFilter) return false;
    }

    // Source filter
    if (sourceFilter !== 'ALL') {
      if (sourceFilter === 'SIEM' && alert.domain !== 'SIEM') return false;
      if (sourceFilter === 'Satellite' && alert.domain !== 'SATELLITE_SPACE') return false;
      if (sourceFilter === 'Sensors' && alert.domain !== 'SENSORS') return false;
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = alert.title?.toLowerCase().includes(q);
      const matchEvent = alert.eventType?.toLowerCase().includes(q);
      const matchAsset = alert.asset?.toLowerCase().includes(q);
      const matchIndicator = alert.indicator?.toLowerCase().includes(q);
      const matchMitre = alert.mitreId?.toLowerCase().includes(q);
      const matchId = alert.alertId.toLowerCase().includes(q);

      if (!matchTitle && !matchEvent && !matchAsset && !matchIndicator && !matchMitre && !matchId) {
        return false;
      }
    }

    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#171717]">
            Security Alerts
          </h1>
          <p className="text-sm text-[#737373] mt-0.5">
            Real-time correlated detections mapped to MITRE ATT&CK with explainable prioritization
          </p>
        </div>

        {/* Total count badge */}
        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 rounded-lg bg-[#f5f5f5] text-[#737373] font-medium border border-[#e5e5e5]">
            Showing <strong className="text-[#171717]">{filteredAlerts.length}</strong> of {alerts.length} alerts
          </span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 p-3 bg-[#f9fafb] border border-[#e5e5e5] rounded-xl">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-[#737373] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search alerts, assets (HOST-042), MITRE (T1059.001)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-white border border-[#e5e5e5] rounded-md pl-9 pr-3 py-1.5 text-xs text-[#171717] placeholder:text-[#737373] focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600 transition-all"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Priority Pills */}
          <div className="flex items-center gap-1 bg-white border border-[#e5e5e5] p-1 rounded-lg">
            <span className="text-[11px] text-[#737373] px-2 font-medium">Priority:</span>
            {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((p) => (
              <button
                key={p}
                onClick={() => setPriorityFilter(p)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                  priorityFilter === p
                    ? 'bg-[#000000] text-white shadow-xs'
                    : 'text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5]'
                }`}
              >
                {p === 'ALL' ? 'All' : p.charAt(0) + p.slice(1).toLowerCase()}
              </button>
            ))}
          </div>

          {/* Source Domain Pills */}
          <div className="flex items-center gap-1 bg-white border border-[#e5e5e5] p-1 rounded-lg">
            <span className="text-[11px] text-[#737373] px-2 font-medium">Source:</span>
            {(['ALL', 'SIEM', 'Satellite', 'Sensors'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSourceFilter(s)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors cursor-pointer ${
                  sourceFilter === s
                    ? 'bg-[#000000] text-white shadow-xs'
                    : 'text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5]'
                }`}
              >
                {s === 'ALL' ? 'All Sources' : s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Alerts Table */}
      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#e5e5e5] bg-[#f9fafb] text-[#737373] text-[11px] font-medium">
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Alert</th>
                <th className="py-3 px-4">Attack Behavior</th>
                <th className="py-3 px-4">MITRE</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#e5e5e5]">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#737373]">
                    No alerts match the selected filters.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const minutesAgo = Math.floor(
                    (Date.now() - new Date(alert.timestamp).getTime()) / 60000
                  );
                  const timeDisplay = minutesAgo <= 1 ? 'Just now' : `${minutesAgo} min ago`;

                  return (
                    <tr
                      key={alert.alertId}
                      onClick={() => setSelectedAlert(alert)}
                      className="hover:bg-[#f9fafb] cursor-pointer transition-colors group"
                    >
                      {/* 1. Priority */}
                      <td className="py-3.5 px-4">
                        <SeverityBadge
                          severity={alert.priority || alert.sourceSeverity}
                          size="sm"
                          variant="sentinel"
                        />
                      </td>

                      {/* 2. Alert */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-[#171717] group-hover:text-blue-600 transition-colors">
                          {alert.title || alert.eventType}
                        </div>
                        <div className="flex items-center gap-2 text-[11px] text-[#737373] mt-0.5">
                          <span className="font-mono text-[#171717] font-medium">{alert.asset || '—'}</span>
                          {alert.indicator && (
                            <>
                              <span>•</span>
                              <span className="truncate max-w-[200px] font-mono text-[#737373]">
                                {alert.indicator}
                              </span>
                            </>
                          )}
                        </div>
                      </td>

                      {/* 3. Attack Behavior */}
                      <td className="py-3.5 px-4">
                        <span className="text-[#171717] font-medium">
                          {alert.attackBehavior || alert.eventType || 'Suspicious activity'}
                        </span>
                      </td>

                      {/* 4. MITRE */}
                      <td className="py-3.5 px-4">
                        {alert.mitreId ? (
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded-md bg-[#f5f5f5] text-[#171717] border border-[#e5e5e5]">
                              {alert.mitreId}
                            </span>
                            {alert.mitreName && (
                              <span className="text-[11px] text-[#737373] hidden sm:inline truncate max-w-[120px]">
                                {alert.mitreName}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-[#a3a3a3]">—</span>
                        )}
                      </td>

                      {/* 5. Source */}
                      <td className="py-3.5 px-4 text-[#737373]">
                        {alert.sourceName}
                      </td>

                      {/* 6. Confidence */}
                      <td className="py-3.5 px-4">
                        {alert.confidence !== undefined ? (
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-[#171717]">
                              {alert.confidence}%
                            </span>
                          </div>
                        ) : (
                          <span className="text-[#a3a3a3]">—</span>
                        )}
                      </td>

                      {/* 7. Time */}
                      <td className="py-3.5 px-4 text-[#737373] whitespace-nowrap">
                        {timeDisplay}
                      </td>

                      {/* 8. Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          className="px-2.5 py-1 rounded-md border border-[#e5e5e5] bg-white text-[#171717] hover:bg-[#f5f5f5] text-[11px] font-medium transition-colors cursor-pointer inline-flex items-center gap-1"
                        >
                          Details <ChevronRight className="w-3 h-3 text-[#737373]" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Clean Slide-Over Alert Detail Panel (Section 6) */}
      <DrawerPanel
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={selectedAlert?.title || selectedAlert?.eventType || 'Alert Intelligence'}
        subtitle={`Alert ID: ${selectedAlert?.alertId} • Observed on ${selectedAlert?.asset || selectedAlert?.sourceName}`}
        width="max-w-2xl"
      >
        {selectedAlert && (
          <div className="space-y-6 text-xs">
            {/* Status, Priority, Confidence Strip */}
            <div className="grid grid-cols-3 gap-3 p-3.5 rounded-xl bg-[#f9fafb] border border-[#e5e5e5]">
              <div>
                <span className="text-[11px] text-[#737373] block font-medium">Status</span>
                <select
                  value={selectedAlert.status || 'Investigating'}
                  onChange={(e) => {
                    const next = e.target.value as Alert['status'];
                    if (next) updateAlertStatus(selectedAlert.alertId, next);
                    setSelectedAlert({ ...selectedAlert, status: next });
                  }}
                  className="mt-1 bg-white border border-[#e5e5e5] rounded-md px-2 py-0.5 text-xs text-[#171717] font-medium focus:outline-none focus:border-blue-600 cursor-pointer"
                >
                  <option value="New">New</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Resolved">Resolved</option>
                  <option value="False Positive">False Positive</option>
                </select>
              </div>

              <div>
                <span className="text-[11px] text-[#737373] block font-medium">Sentinel-X Priority</span>
                <div className="mt-1.5">
                  <SeverityBadge severity={selectedAlert.priority || selectedAlert.sourceSeverity} size="sm" variant="sentinel" />
                </div>
              </div>

              <div>
                <span className="text-[11px] text-[#737373] block font-medium">Detection Confidence</span>
                <div className="flex items-center gap-1.5 mt-1">
                  <span className="font-mono font-bold text-sm text-[#171717]">
                    {selectedAlert.confidence}%
                  </span>
                  {selectedAlert.correlationConfidence && (
                    <span className="text-[10px] text-[#737373]">
                      (Corr: {selectedAlert.correlationConfidence}%)
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* WHAT HAPPENED? */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-2">
                What Happened?
              </h3>
              <div className="p-3.5 rounded-xl bg-white border border-[#e5e5e5] text-sm text-[#171717] leading-relaxed">
                {selectedAlert.whatHappened ||
                  'Suspicious behavior detected and correlated across ingestion telemetry.'}
              </div>
            </div>

            {/* ATTACK BEHAVIOR */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-2">
                Attack Behavior
              </h3>
              <div className="p-3.5 rounded-xl bg-white border border-[#e5e5e5] flex items-center justify-between">
                <div>
                  <span className="font-semibold text-sm text-[#171717] block">
                    {selectedAlert.attackBehavior || 'Command execution'}
                  </span>
                  <span className="text-[11px] text-[#737373]">
                    Behavioral vector identified from process telemetry
                  </span>
                </div>
                {selectedAlert.behavioralMatch && (
                  <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                    {selectedAlert.behavioralMatch}
                  </span>
                )}
              </div>
            </div>

            {/* SATELLITE ANOMALY SPECIFIC CALLOUT (If applicable) */}
            {selectedAlert.telemetryDetail && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-2">
                  Space Telemetry Anomaly (Operational Context)
                </h3>
                <div className="p-3.5 rounded-xl bg-amber-50/70 border border-amber-200 space-y-2">
                  <div className="flex items-center justify-between text-xs text-amber-900">
                    <span className="font-medium">{selectedAlert.telemetryDetail.parameter}</span>
                    <span className="font-mono font-bold text-amber-800">
                      Deviation: {selectedAlert.telemetryDetail.deviation}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 rounded-lg bg-white border border-amber-200">
                      <span className="text-[10px] text-[#737373] block">Observed Value</span>
                      <span className="font-mono font-bold text-[#171717] text-sm">
                        {selectedAlert.telemetryDetail.observed}
                      </span>
                    </div>
                    <div className="p-2 rounded-lg bg-white border border-amber-200">
                      <span className="text-[10px] text-[#737373] block">Expected Baseline</span>
                      <span className="font-mono font-bold text-[#171717] text-sm">
                        {selectedAlert.telemetryDetail.expected}
                      </span>
                    </div>
                  </div>
                  <p className="text-[11px] text-amber-800 font-medium pt-1">
                    Important: Sentinel-X classifies this as an operational telemetry anomaly. It is strictly isolated from confirmed cyberattacks without independent cyber indicators.
                  </p>
                </div>
              </div>
            )}

            {/* MITRE ATT&CK MAPPING (Section 8: Presented as Intelligence Enrichment Layer) */}
            {selectedAlert.mitreId && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373]">
                    MITRE ATT&CK Mapping
                  </h3>
                  <span className="text-[10px] text-[#737373] font-medium">
                    Intelligence Enrichment Layer
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-white border border-[#e5e5e5] space-y-2.5">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono font-bold text-xs bg-[#f5f5f5] text-[#171717] px-2.5 py-1 rounded-md border border-[#e5e5e5]">
                      {selectedAlert.mitreId}
                    </span>
                    <span className="font-semibold text-sm text-[#171717]">
                      {selectedAlert.mitreName}
                    </span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                      Tactic: {selectedAlert.mitreTactic}
                    </span>
                  </div>
                  <p className="text-xs text-[#737373] leading-relaxed">
                    {selectedAlert.mitreDescription}
                  </p>
                  <div className="pt-2 border-t border-[#e5e5e5] text-[11px] text-[#737373]">
                    <strong>Note:</strong> Technique mapping enriches contextual understanding; final priority is calculated by Sentinel-X organizational assessment.
                  </div>
                </div>
              </div>
            )}

            {/* WHY WAS THIS PRIORITIZED? (Section 6 & 9) */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-2">
                Why Was This Prioritized?
              </h3>
              <div className="p-4 rounded-xl bg-white border border-[#e5e5e5] space-y-3">
                {/* Source Severity vs Sentinel-X Priority */}
                <div className="flex items-center gap-3 p-2.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] text-xs">
                  <span className="text-[#737373]">Source severity:</span>
                  <SeverityBadge severity={selectedAlert.sourceSeverity} size="sm" variant="source" />
                  <span className="text-[#a3a3a3]">→</span>
                  <span className="text-[#737373]">Sentinel-X priority:</span>
                  <SeverityBadge severity={selectedAlert.priority} size="sm" variant="sentinel" />
                </div>

                {selectedAlert.priorityReason && (
                  <p className="text-xs font-medium text-blue-900 bg-blue-50/80 p-2.5 rounded-lg border border-blue-100">
                    <strong>Reason:</strong> {selectedAlert.priorityReason}
                  </p>
                )}

                <div className="space-y-2 pt-1">
                  {(selectedAlert.whyPrioritized || [
                    '+ Strong behavioral match to attack vector',
                    '+ Multiple related events within temporal proximity',
                    '+ High-confidence ML detection model score',
                  ]).map((factor, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-[#171717]">
                      <span className="text-blue-600 font-bold leading-none mt-0.5">•</span>
                      <span>{factor}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* EVIDENCE (Source Events Timeline) */}
            {selectedAlert.evidenceTimeline && selectedAlert.evidenceTimeline.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-2">
                  Evidence Timeline
                </h3>
                <div className="p-4 rounded-xl bg-white border border-[#e5e5e5] space-y-3">
                  <div className="relative border-l border-[#e5e5e5] ml-2 pl-4 space-y-3">
                    {selectedAlert.evidenceTimeline.map((item, idx) => (
                      <div key={idx} className="relative">
                        <div className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-blue-600 ring-4 ring-white" />
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-[#171717]">
                            {item.time}
                          </span>
                          <span className="text-[10px] px-2 py-0.2 rounded-full bg-[#f5f5f5] text-[#737373] font-medium border border-[#e5e5e5]">
                            {item.source}
                          </span>
                        </div>
                        <div className="font-semibold text-xs text-[#171717] mt-0.5">
                          {item.event}
                        </div>
                        <div className="text-[11px] text-[#737373] mt-0.5 font-mono">
                          {item.detail}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* RECOMMENDED ACTION */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-2">
                Recommended Action
              </h3>
              <div className="p-4 rounded-xl bg-emerald-50/70 border border-emerald-200 text-emerald-900 text-xs font-medium leading-relaxed flex items-start gap-2.5">
                <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold block mb-0.5">Analyst Guidance</span>
                  {selectedAlert.recommendedAction || 'Review host telemetry and validate command parameters.'}
                </div>
              </div>
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
