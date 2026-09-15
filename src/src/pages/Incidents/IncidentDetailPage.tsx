import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { RiskGauge } from '../../components/ui/RiskGauge';
import { ConfidenceMeter } from '../../components/ui/ConfidenceMeter';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  Check,
  X,
  FileText,
  Sliders,
  Sparkles,
  ExternalLink,
  Layers,
  Network,
  Cpu,
  Clock,
  HelpCircle,
} from 'lucide-react';
import { defaultWeights } from '../../services/riskEngine';

export const IncidentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { incidents, alerts } = useSentinel();

  const incident = incidents.find((i) => i.incidentId === id) || incidents[0];
  const relatedAlerts = alerts.filter((a) => incident.correlatedAlertIds.includes(a.alertId));

  const [weights, setWeights] = useState(defaultWeights);
  const [showWeightSliders, setShowWeightSliders] = useState(false);

  // Dynamic score recalculation based on interactive weights
  const interactiveScore = Math.round(
    incident.riskFactors.evidenceStrength * weights.evidenceStrength +
    incident.riskFactors.assetCriticality * weights.assetCriticality +
    incident.riskFactors.correlationStrength * weights.correlationStrength +
    incident.riskFactors.threatIntelConfidence * weights.threatIntelConfidence +
    incident.riskFactors.temporalCorrelation * weights.temporalCorrelation
  );

  return (
    <div className="space-y-6">
      {/* Top Navigation Bar */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/incidents')}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Incidents
        </button>

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/bluf')}
            className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-bold text-xs flex items-center gap-1.5 shadow-md shadow-cyan-950 transition-colors cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" /> View Commander BLUF
          </button>
        </div>
      </div>

      {/* Hero Incident Header */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-sm p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1f293d]">
          <div className="flex items-start gap-5">
            <RiskGauge score={interactiveScore} size={96} />
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-2xl font-black font-mono text-cyan-400">
                  {incident.incidentId}
                </h1>
                <SeverityBadge severity={incident.priority} size="md" variant="sentinel" />
                <span className="text-xs px-2.5 py-0.5 rounded font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                  Status: {incident.status}
                </span>
                <span className="text-xs px-2.5 py-0.5 rounded font-mono bg-cyan-950/60 text-cyan-400 border border-cyan-800">
                  {incident.evidenceDomains.join(' + ')}
                </span>
              </div>

              <div className="mt-3 flex items-center gap-4 text-xs font-mono text-slate-300">
                <span>
                  Affected Asset:{' '}
                  <strong className="text-slate-100 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                    {incident.affectedAsset}
                  </strong>
                </span>
                <span>
                  First Seen:{' '}
                  <span className="text-slate-400">{new Date(incident.firstSeen).toUTCString()}</span>
                </span>
              </div>

              <p className="text-xs text-slate-300 mt-2 max-w-3xl leading-relaxed">
                {incident.blufSummary}
              </p>
            </div>
          </div>

          {/* Key Metrics Columns: Confidence vs Data Completeness */}
          <div className="w-full lg:w-72 bg-slate-900/80 p-4 rounded border border-slate-800 space-y-3 shrink-0">
            <div className="text-xs font-mono text-slate-400 font-bold uppercase tracking-wider pb-1 border-b border-slate-800">
              Confidence vs Completeness
            </div>
            <ConfidenceMeter
              value={incident.confidence}
              label="Assessment Confidence"
              showPercent
            />
            <ConfidenceMeter
              value={incident.dataCompleteness}
              label="Data Completeness"
              type="completeness"
              showPercent
            />
            <p className="text-[10px] text-slate-500 font-mono italic">
              Note: Sparse data completeness is evaluated independently. Missing fields do not
              artificially reduce risk.
            </p>
          </div>
        </div>

        {/* Section 19: Source Severity vs Sentinel-X Priority Comparison Strip */}
        <div className="mt-5 p-4 bg-slate-950/70 rounded border border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                Source Severity vs Sentinel-X Priority Distinction
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                Architectural Distinction
              </span>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Raw source reports are correlated into explainable operational priority
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-6 gap-3 font-mono text-xs">
            {/* Raw sources */}
            {incident.sourceSeverities.map((item, idx) => (
              <div key={idx} className="p-2.5 bg-slate-900/80 border border-slate-800 rounded">
                <span className="text-[10px] text-slate-400 block truncate">{item.source}</span>
                <div className="mt-1">
                  <SeverityBadge severity={item.severity} size="sm" variant="source" />
                </div>
                <span className="text-[9px] text-slate-500 block mt-1">Source Severity</span>
              </div>
            ))}

            {/* Sentinel-X Final Priority */}
            <div className="p-2.5 bg-cyan-950/40 border border-cyan-700/60 rounded col-span-1 md:col-span-1 shadow-sm">
              <span className="text-[10px] text-cyan-300 block font-bold">SENTINEL-X PRIORITY</span>
              <div className="mt-1">
                <SeverityBadge severity={incident.sentinelPriority} size="sm" variant="sentinel" />
              </div>
              <span className="text-[9px] text-cyan-400 block mt-1 font-bold">
                Computed Score {interactiveScore}/100
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Correlation Logic UI & False Positive Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Correlation Visualization: Why events were grouped together */}
        <div className="lg:col-span-7">
          <Card
            title="Correlation Engine Corroboration"
            subtitle="Transparent multi-source correlation criteria"
          >
            <div className="space-y-4 font-mono text-xs">
              <p className="text-slate-300 text-xs">
                Sentinel-X does NOT use a black-box model. Events are aggregated based on explicit,
                verifiable cross-source correlation proofs:
              </p>

              {/* Correlation Graph Diagram */}
              <div className="p-4 bg-slate-950 rounded border border-slate-800 text-center">
                <div className="inline-block bg-cyan-950/80 border border-cyan-700 text-cyan-300 font-bold px-4 py-1.5 rounded mb-3">
                  INCIDENT {incident.incidentId} (Target: {incident.affectedAsset})
                </div>
                <div className="flex items-center justify-center gap-6 py-2 text-slate-500 text-sm">
                  <span>│</span>
                  <span>│</span>
                  <span>│</span>
                </div>
                <div className="grid grid-cols-3 gap-2 max-w-md mx-auto">
                  <div className="p-2 bg-slate-900 border border-slate-700 rounded text-sky-400 text-[11px]">
                    <Network className="w-4 h-4 mx-auto mb-1 text-sky-400" />
                    SIEM Logs
                    <span className="block text-[9px] text-slate-400">Tor C2 / Mimikatz</span>
                  </div>
                  <div className="p-2 bg-slate-900 border border-slate-700 rounded text-emerald-400 text-[11px]">
                    <Cpu className="w-4 h-4 mx-auto mb-1 text-emerald-400" />
                    Sensors
                    <span className="block text-[9px] text-slate-400">LSASS / Process Spawn</span>
                  </div>
                  <div className="p-2 bg-slate-900 border border-slate-700 rounded text-purple-400 text-[11px]">
                    <Layers className="w-4 h-4 mx-auto mb-1 text-purple-400" />
                    Threat Intel / KEV
                    <span className="block text-[9px] text-slate-400">APT29 / PrintNightmare</span>
                  </div>
                </div>
              </div>

              {/* Corroboration Evidence Checklist */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {[
                  { label: 'Same Asset Identifier', match: incident.corroboration.sameAsset },
                  { label: 'Same Indicator (IP/Hash)', match: incident.corroboration.sameIndicator },
                  { label: 'Temporal Proximity (< 5m)', match: incident.corroboration.temporalProximity },
                  { label: 'Multiple Independent Sources', match: incident.corroboration.multipleIndependentSources },
                  { label: 'Similar Behavioral Pattern', match: incident.corroboration.similarBehavior },
                  { label: 'Threat Intelligence Corroboration', match: incident.corroboration.threatIntelMatch },
                  { label: 'CISA KEV Vulnerability Match', match: incident.corroboration.cisaKevMatch },
                ].map((item, idx) => (
                  <div
                    key={idx}
                    className={`p-2.5 rounded border flex items-center justify-between ${
                      item.match
                        ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
                        : 'bg-slate-900/40 border-slate-800 text-slate-500'
                    }`}
                  >
                    <span className="text-[11px] font-semibold">{item.label}</span>
                    {item.match ? (
                      <span className="flex items-center gap-1 font-bold text-emerald-400">
                        <Check className="w-3.5 h-3.5" /> VERIFIED
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-slate-500">
                        <X className="w-3.5 h-3.5" /> NOT MET
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </Card>
        </div>

        {/* False Positive Analysis Panel */}
        <div className="lg:col-span-5">
          <Card
            title="False Positive Triage"
            subtitle="AI Confidence & Assessment Justification"
          >
            <div className="space-y-4 font-mono text-xs">
              <div
                className={`p-4 rounded border ${
                  incident.threatAssessment === 'LIKELY_THREAT'
                    ? 'bg-red-950/40 border-red-800/80 text-red-300'
                    : incident.threatAssessment === 'LIKELY_FALSE_POSITIVE'
                    ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                    : 'bg-amber-950/40 border-amber-800/80 text-amber-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {incident.threatAssessment === 'LIKELY_THREAT' ? (
                      <ShieldAlert className="w-5 h-5 text-red-400" />
                    ) : incident.threatAssessment === 'LIKELY_FALSE_POSITIVE' ? (
                      <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-amber-400" />
                    )}
                    <span className="font-bold text-sm">
                      {incident.threatAssessment.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-900">
                    Confidence: {incident.confidence}%
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] uppercase tracking-wider font-bold block mb-2">
                  Triage Rationale & Evidence Points:
                </span>
                <ul className="space-y-2">
                  {incident.threatAssessmentReasons.map((reason, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2 p-2 bg-slate-900/60 rounded border border-slate-800 text-slate-300 text-[11px]"
                    >
                      <span
                        className={
                          incident.threatAssessment === 'LIKELY_FALSE_POSITIVE'
                            ? 'text-emerald-400 font-bold'
                            : 'text-red-400 font-bold'
                        }
                      >
                        {incident.threatAssessment === 'LIKELY_FALSE_POSITIVE' ? '—' : '+'}
                      </span>
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {incident.cveIds?.length > 0 && (
                <div className="p-3 bg-red-950/20 border border-red-900/50 rounded">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-red-300 text-xs">
                      CISA KEV Vulnerability Matched:
                    </span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-900/80 text-red-200">
                      Active Exploit
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] mt-1">
                    {incident.cveIds.join(', ')} — PrintNightmare RCE on Windows Print Spooler. KEV
                    inclusion confirms active exploitation in the wild.
                  </p>
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>

      {/* Explainable Risk Engine Factor Breakdown */}
      <Card
        title="Explainable Risk Engine Breakdown"
        subtitle="Transparent Factor Scoring & Configurable Policy Weights"
        headerAction={
          <button
            onClick={() => setShowWeightSliders(!showWeightSliders)}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 cursor-pointer"
          >
            <Sliders className="w-3.5 h-3.5" />
            {showWeightSliders ? 'Hide Policy Sliders' : 'Configure Policy Weights'}
          </button>
        }
      >
        <div className="space-y-4 font-mono text-xs">
          <p className="text-slate-400 text-xs">
            Risk is calculated deterministically via weighted multi-factor policy. It is{' '}
            <strong className="text-slate-200">configurable organizational policy</strong>, not an
            arbitrary black box.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
            {[
              {
                label: 'Evidence Strength',
                value: incident.riskFactors.evidenceStrength,
                weight: weights.evidenceStrength,
                key: 'evidenceStrength',
              },
              {
                label: 'Asset Criticality',
                value: incident.riskFactors.assetCriticality,
                weight: weights.assetCriticality,
                key: 'assetCriticality',
              },
              {
                label: 'Correlation Strength',
                value: incident.riskFactors.correlationStrength,
                weight: weights.correlationStrength,
                key: 'correlationStrength',
              },
              {
                label: 'Threat Intel Conf.',
                value: incident.riskFactors.threatIntelConfidence,
                weight: weights.threatIntelConfidence,
                key: 'threatIntelConfidence',
              },
              {
                label: 'Temporal Correlation',
                value: incident.riskFactors.temporalCorrelation,
                weight: weights.temporalCorrelation,
                key: 'temporalCorrelation',
              },
            ].map((factor) => (
              <div
                key={factor.label}
                className="p-3 bg-slate-900/80 border border-slate-800 rounded space-y-2"
              >
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>{factor.label}</span>
                  <span className="font-bold text-slate-200">{factor.value}</span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-cyan-400 h-full rounded-full"
                    style={{ width: `${factor.value}%` }}
                  />
                </div>
                <div className="text-[10px] text-slate-500 flex items-center justify-between">
                  <span>Policy Weight:</span>
                  <span className="text-cyan-400 font-bold">{Math.round(factor.weight * 100)}%</span>
                </div>
              </div>
            ))}
          </div>

          {/* Interactive Weight Sliders (Organizational Policy) */}
          {showWeightSliders && (
            <div className="p-4 bg-slate-950 border border-slate-800 rounded space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-200 text-xs">
                  Organizational Policy Weight Tuning:
                </span>
                <span className="text-xs text-amber-400">
                  Simulated Real-Time Re-weighting
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
                {Object.keys(weights).map((key) => {
                  const factorKey = key as keyof typeof weights;
                  return (
                    <div key={key} className="space-y-1">
                      <div className="flex justify-between text-[10px] text-slate-400">
                        <span className="capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                        <span className="text-cyan-400 font-bold">
                          {Math.round(weights[factorKey] * 100)}%
                        </span>
                      </div>
                      <input
                        type="range"
                        min="0"
                        max="0.6"
                        step="0.05"
                        value={weights[factorKey]}
                        onChange={(e) =>
                          setWeights({ ...weights, [factorKey]: parseFloat(e.target.value) })
                        }
                        className="w-full accent-cyan-400 cursor-pointer"
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="p-3 bg-slate-900 border border-slate-800 rounded text-slate-300 text-xs">
            <strong className="text-cyan-400">Explainable AI Justification: </strong>
            "Risk is scored at {interactiveScore}/100 because multiple independent telemetry feeds
            (SIEM logs, endpoint EDR, and network sensor) corroborate an active killchain on
            critical asset [{incident.affectedAsset}] within a 4-minute time window, reinforced by
            known malicious indicators in CTI and active CISA KEV exploitation."
          </div>
        </div>
      </Card>

      {/* Correlated Alerts Sub-table */}
      <Card
        title={`Correlated Ingested Evidence (${relatedAlerts.length} Events)`}
        subtitle="Atomic alerts associated with this incident cluster"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/60 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Domain</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Indicator</th>
                <th className="py-2.5 px-3">Source Severity</th>
                <th className="py-2.5 px-3">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {relatedAlerts.map((alert) => (
                <tr key={alert.alertId} className="hover:bg-slate-800/40">
                  <td className="py-2.5 px-3 font-bold text-cyan-400">{alert.alertId}</td>
                  <td className="py-2.5 px-3 text-slate-400">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">
                      {alert.domain}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 font-semibold">{alert.sourceName}</td>
                  <td className="py-2.5 px-3 text-slate-200">{alert.eventType || '—'}</td>
                  <td className="py-2.5 px-3 text-cyan-300">{alert.indicator || '—'}</td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={alert.sourceSeverity} size="sm" variant="source" />
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {alert.confidence ? `${alert.confidence}%` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
