import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { RiskGauge } from '../../components/ui/RiskGauge';
import {
  ArrowLeft,
  ShieldAlert,
  Radio,
  FileText,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  ExternalLink,
  Sliders,
} from 'lucide-react';
import { defaultWeights } from '../../services/riskEngine';

export const IncidentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { incidents, alerts } = useSentinel();

  const incident = incidents.find((i) => i.incidentId === id) || incidents[0];
  const relatedAlerts = alerts.filter((a) => incident.correlatedAlertIds.includes(a.alertId));

  const [showCorrelationDetails, setShowCorrelationDetails] = useState<boolean>(false);
  const [showBlufModal, setShowBlufModal] = useState<boolean>(false);

  return (
    <div className="space-y-6 pb-12">
      {/* Top Breadcrumb / Back */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/incidents')}
          className="inline-flex items-center gap-1.5 text-xs text-[#737373] hover:text-[#171717] font-medium transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Incidents
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowBlufModal(true)}
            className="px-3 py-1.5 rounded-lg border border-[#e5e5e5] bg-white text-[#171717] hover:bg-[#f5f5f5] text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
          >
            <FileText className="w-3.5 h-3.5 text-blue-600" /> Executive BLUF
          </button>
        </div>
      </div>

      {/* Incident Hero Header Card */}
      <div className="bg-white border border-[#e5e5e5] rounded-xl p-6 shadow-[0_1px_2px_rgba(0,0,0,0.03)]">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#e5e5e5]">
          <div className="flex items-start gap-5">
            <RiskGauge score={incident.riskScore} size={90} />
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="font-mono font-bold text-xs bg-[#f5f5f5] text-[#171717] px-2 py-0.5 rounded-md border border-[#e5e5e5]">
                  {incident.incidentId}
                </span>
                <h1 className="text-xl font-bold text-[#171717]">
                  {incident.title}
                </h1>
                <SeverityBadge severity={incident.priority} size="sm" variant="sentinel" />
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-[#f5f5f5] text-[#737373] border border-[#e5e5e5]">
                  Status: {incident.status}
                </span>
              </div>

              <div className="mt-2.5 flex items-center gap-4 text-xs text-[#737373] flex-wrap">
                <span>
                  Target Asset:{' '}
                  <strong className="text-[#171717] font-mono bg-[#f5f5f5] px-2 py-0.5 rounded border border-[#e5e5e5]">
                    {incident.affectedAsset}
                  </strong>
                </span>
                <span>•</span>
                <span>
                  First Seen: <span className="text-[#171717] font-medium">{new Date(incident.firstSeen).toLocaleTimeString()}</span>
                </span>
                <span>•</span>
                <span>
                  Assessment Confidence:{' '}
                  <strong className="text-[#171717] font-mono">{incident.confidence}%</strong>
                </span>
              </div>

              <p className="text-xs text-[#737373] mt-3 leading-relaxed max-w-3xl">
                {incident.blufSummary}
              </p>
            </div>
          </div>
        </div>

        {/* Source Severities vs Sentinel-X Priority (Section 9) */}
        <div className="pt-4 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
            <span className="text-[11px] text-[#737373] block mb-1">Source Reported Severities</span>
            <div className="flex flex-wrap gap-1.5">
              {incident.sourceSeverities.map((s, idx) => (
                <span key={idx} className="flex items-center gap-1 text-[11px] font-medium text-[#171717]">
                  <span className="text-[#737373]">{s.source}:</span>
                  <SeverityBadge severity={s.severity} size="sm" variant="source" />
                </span>
              ))}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
            <span className="text-[11px] text-[#737373] block mb-1">Sentinel-X Assessed Priority</span>
            <div className="flex items-center gap-2 mt-1">
              <SeverityBadge severity={incident.priority} size="sm" variant="sentinel" />
              <span className="text-[11px] text-[#737373]">
                (Multi-factor explainable policy)
              </span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
            <span className="text-[11px] text-[#737373] block mb-1">Reason for Assessment</span>
            <p className="text-xs text-[#171717] font-medium mt-1">
              Multiple correlated events across independent sources within a 7-minute window elevated assessed priority.
            </p>
          </div>
        </div>
      </div>

      {/* Attack Progression Timeline (Section 14) */}
      <Card
        title="Attack Progression Timeline"
        subtitle="Chronological sequence of correlated adversary behavior"
      >
        <div className="relative border-l-2 border-[#e5e5e5] ml-4 pl-6 space-y-6 py-2">
          {(incident.timeline || []).map((step, idx) => (
            <div key={idx} className="relative">
              <div className="absolute -left-[31px] top-1 w-3 h-3 rounded-full bg-blue-600 ring-4 ring-white shadow-xs" />
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm font-bold text-[#171717]">
                  {step.time}
                </span>
                <span className="text-xs font-semibold text-blue-700 bg-blue-50 px-2.5 py-0.5 rounded-full border border-blue-200">
                  {step.stage}
                </span>
                {step.mitre && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#f5f5f5] text-[#171717] border border-[#e5e5e5]">
                    MITRE {step.mitre}
                  </span>
                )}
                <span className="text-xs text-[#737373] ml-auto">
                  Source: {step.source}
                </span>
              </div>
              <p className="text-xs text-[#171717] mt-1.5 leading-relaxed">
                {step.description}
              </p>
            </div>
          ))}
        </div>
      </Card>

      {/* Related Alerts in this Incident */}
      <Card
        title="Correlated Alerts"
        subtitle={`${relatedAlerts.length} security events contributing to this incident`}
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px] text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#e5e5e5] bg-[#f9fafb] text-[#737373] text-[11px] font-medium">
                <th className="py-2.5 px-3">Alert</th>
                <th className="py-2.5 px-3">Attack Behavior</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">MITRE</th>
                <th className="py-2.5 px-3">Source Severity</th>
                <th className="py-2.5 px-3">Assessed Priority</th>
                <th className="py-2.5 px-3 text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#e5e5e5]">
              {relatedAlerts.map((alert) => (
                <tr key={alert.alertId} className="hover:bg-[#f9fafb]">
                  <td className="py-2.5 px-3 font-semibold text-[#171717]">
                    {alert.title || alert.eventType}
                  </td>
                  <td className="py-2.5 px-3 text-[#171717]">
                    {alert.attackBehavior || alert.eventType}
                  </td>
                  <td className="py-2.5 px-3 text-[#737373]">
                    {alert.sourceName}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px]">
                    {alert.mitreId || '—'}
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={alert.sourceSeverity} size="sm" variant="source" />
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={alert.priority} size="sm" variant="sentinel" />
                  </td>
                  <td className="py-2.5 px-3 text-right font-mono font-medium text-[#171717]">
                    {alert.confidence}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Collapsible Correlation Details (Prompt Section 14: Not on the main page by default) */}
      <div className="bg-white border border-[#e5e5e5] rounded-xl overflow-hidden shadow-[0_1px_2px_rgba(0,0,0,0.03)]">
        <button
          onClick={() => setShowCorrelationDetails(!showCorrelationDetails)}
          className="w-full px-5 py-4 flex items-center justify-between bg-[#f9fafb] hover:bg-[#f5f5f5] transition-colors cursor-pointer text-left"
        >
          <div>
            <h3 className="text-sm font-semibold text-[#171717]">
              View Correlation Details
            </h3>
            <p className="text-xs text-[#737373] mt-0.5">
              Technical multi-source corroboration factors and correlation matrices
            </p>
          </div>
          <div className="flex items-center gap-1 text-xs text-[#737373]">
            <span>{showCorrelationDetails ? 'Hide details' : 'Show details'}</span>
            {showCorrelationDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {showCorrelationDetails && (
          <div className="p-5 border-t border-[#e5e5e5] space-y-4 text-xs">
            <h4 className="font-semibold text-xs text-[#171717] uppercase tracking-wider">
              Corroboration Matrix
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <span className="text-[11px] text-[#737373] block">Same Asset</span>
                <span className="font-semibold text-[#171717] mt-1 block">
                  {incident.corroboration.sameAsset ? '✓ Verified (HOST-042)' : '✗ Not matched'}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <span className="text-[11px] text-[#737373] block">Temporal Proximity</span>
                <span className="font-semibold text-[#171717] mt-1 block">
                  {incident.corroboration.temporalProximity ? '✓ Within 7 mins' : '✗ Outside window'}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <span className="text-[11px] text-[#737373] block">Independent Sources</span>
                <span className="font-semibold text-[#171717] mt-1 block">
                  {incident.corroboration.multipleIndependentSources ? '✓ EDR + SIEM' : '✗ Single source'}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <span className="text-[11px] text-[#737373] block">CISA KEV Match</span>
                <span className="font-semibold text-[#171717] mt-1 block">
                  {incident.corroboration.cisaKevMatch ? '✓ Active Exploit' : '✗ No match'}
                </span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-blue-50/60 border border-blue-200 text-blue-900 text-xs">
              <strong>ML Correlation Match:</strong> Behavioral trajectory aligns with lateral movement sequence. Confidence score is 94% across 4 correlated events.
            </div>
          </div>
        )}
      </div>

      {/* BLUF Modal */}
      {showBlufModal && (
        <div className="fixed inset-0 z-50 overflow-hidden flex items-center justify-center p-4">
          <div className="fixed inset-0 bg-black/30 backdrop-blur-xs" onClick={() => setShowBlufModal(false)} />
          <div className="relative bg-white border border-[#e5e5e5] rounded-xl shadow-xl max-w-2xl w-full p-6 space-y-4 z-10">
            <div className="flex items-center justify-between pb-3 border-b border-[#e5e5e5]">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-[#171717]">
                  Executive BLUF Report (Bottom Line Up Front)
                </h3>
              </div>
              <button
                onClick={() => setShowBlufModal(false)}
                className="text-[#737373] hover:text-[#171717] text-xs font-semibold px-2 py-1 rounded-md"
              >
                Close
              </button>
            </div>
            <div className="space-y-3 text-xs">
              <div className="p-3 bg-red-50 text-red-900 border border-red-200 rounded-lg font-medium">
                <strong>BOTTOM LINE:</strong> Multi-stage intrusion actively targeting critical asset HOST-042 with credential theft and encoded execution.
              </div>
              <p className="text-[#171717] leading-relaxed">
                {incident.blufSummary}
              </p>
              <div className="p-3 bg-[#f9fafb] border border-[#e5e5e5] rounded-lg space-y-1">
                <span className="font-semibold text-[#171717] block">Recommended Immediate Actions:</span>
                <ul className="list-disc list-inside space-y-1 text-[#737373]">
                  <li>Isolate host HOST-042 from internal corporate network</li>
                  <li>Rotate Kerberos service tickets for database admin credentials</li>
                  <li>Block outbound connection to destination IP 198.51.100.42</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
