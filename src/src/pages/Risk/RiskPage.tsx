import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { RiskGauge } from '../../components/ui/RiskGauge';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { defaultWeights, riskEngine } from '../../services/riskEngine';
import { Scale, HelpCircle, ShieldCheck, FileCheck, Sliders, CheckCircle2 } from 'lucide-react';
import { RiskWeights } from '../../types';

export const RiskPage: React.FC = () => {
  const { incidents, selectedIncidentId, setSelectedIncidentId, updateIncidentWeights } =
    useSentinel();

  const selectedIncident =
    incidents.find((i) => i.incidentId === selectedIncidentId) || incidents[0];

  const [weights, setWeights] = useState<RiskWeights>(defaultWeights);
  const [showExplanation, setShowExplanation] = useState<boolean>(true);

  const calculatedScore = riskEngine.calculateScore(selectedIncident.riskFactors, weights);
  const priority = riskEngine.calculatePriority(calculatedScore);
  const explanation = riskEngine.generateExplanation(
    selectedIncident.riskFactors,
    calculatedScore,
    selectedIncident.affectedAsset
  );

  const handleWeightChange = (key: keyof RiskWeights, value: number) => {
    const updated = { ...weights, [key]: value };
    setWeights(updated);
    updateIncidentWeights(selectedIncident.incidentId, updated);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          EXPLAINABLE RISK SCORING ENGINE
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          Transparent multi-factor priority calculation governed by organizational policy
        </p>
      </div>

      {/* Incident Selector */}
      <div className="flex flex-wrap items-center gap-2 bg-slate-900/80 p-2.5 rounded border border-slate-800 font-mono text-xs">
        <span className="text-slate-400 font-bold uppercase text-[11px]">Select Target Incident:</span>
        {incidents.map((inc) => (
          <button
            key={inc.incidentId}
            onClick={() => setSelectedIncidentId(inc.incidentId)}
            className={`px-3 py-1.5 rounded transition-colors font-semibold cursor-pointer ${
              inc.incidentId === selectedIncident.incidentId
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {inc.incidentId} — {inc.affectedAsset} ({inc.priority})
          </button>
        ))}
      </div>

      {/* Hero: Score & Priority Overview */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-sm p-6 shadow-xl flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-6">
          <RiskGauge score={calculatedScore} size={110} />
          <div>
            <div className="flex items-center gap-3">
              <span className="text-lg font-black font-mono text-slate-100">
                {selectedIncident.incidentId} RISK EVALUATION
              </span>
              <SeverityBadge severity={priority} size="md" variant="sentinel" />
            </div>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Target Asset: <strong className="text-slate-200">{selectedIncident.affectedAsset}</strong>
            </p>
            <div className="mt-2 text-[11px] font-mono text-slate-400">
              Correlated Domains: {selectedIncident.evidenceDomains.join(', ')} • {selectedIncident.correlatedAlertIds.length} telemetry records
            </div>
          </div>
        </div>

        <div className="text-right font-mono">
          <span className="text-[10px] text-amber-400/90 uppercase tracking-widest block font-bold">
            Policy Governance Notice
          </span>
          <span className="text-xs text-slate-400 max-w-xs block mt-1">
            Scoring formula reflects configurable organizational policy, not an opaque black-box.
          </span>
        </div>
      </div>

      {/* Factor Breakdown & Sliders */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Factors List */}
        <div className="lg:col-span-7">
          <Card
            title="Risk Factor Decomposition"
            subtitle="Observed factor values for current incident"
          >
            <div className="space-y-4 font-mono text-xs">
              {[
                {
                  key: 'evidenceStrength' as const,
                  label: 'Evidence Strength',
                  desc: 'Volume and diversity of corroborating telemetry reports',
                  value: selectedIncident.riskFactors.evidenceStrength,
                },
                {
                  key: 'assetCriticality' as const,
                  label: 'Asset Criticality',
                  desc: 'Operational mission tier of the affected asset',
                  value: selectedIncident.riskFactors.assetCriticality,
                },
                {
                  key: 'correlationStrength' as const,
                  label: 'Correlation Strength',
                  desc: 'Mathematical convergence across independent domains',
                  value: selectedIncident.riskFactors.correlationStrength,
                },
                {
                  key: 'threatIntelConfidence' as const,
                  label: 'Threat Intelligence Confidence',
                  desc: 'Attribution confidence from verified CTI indicators',
                  value: selectedIncident.riskFactors.threatIntelConfidence,
                },
                {
                  key: 'temporalCorrelation' as const,
                  label: 'Temporal Correlation',
                  desc: 'Clustering density within configured sliding window',
                  value: selectedIncident.riskFactors.temporalCorrelation,
                },
              ].map((factor) => (
                <div key={factor.key} className="p-3 bg-slate-900/70 rounded border border-slate-800">
                  <div className="flex items-center justify-between mb-1">
                    <div>
                      <span className="font-bold text-slate-200 text-sm">{factor.label}</span>
                      <p className="text-[11px] text-slate-500">{factor.desc}</p>
                    </div>
                    <div className="text-right">
                      <span className="font-bold text-cyan-300 text-base">{factor.value}</span>
                      <span className="text-[10px] text-slate-500"> / 100</span>
                    </div>
                  </div>

                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mt-2">
                    <div
                      className="bg-cyan-400 h-full rounded-full transition-all duration-500"
                      style={{ width: `${factor.value}%` }}
                    />
                  </div>

                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                    <span>Applied Weight: {Math.round(weights[factor.key] * 100)}%</span>
                    <span>
                      Factor Contribution:{' '}
                      <strong className="text-slate-200">
                        {Math.round(factor.value * weights[factor.key])} pts
                      </strong>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Policy Weights Tuning & Explanation */}
        <div className="lg:col-span-5 space-y-6">
          <Card
            title="Organizational Policy Weights"
            subtitle="Adjust policy weighting parameters"
          >
            <div className="space-y-4 font-mono text-xs">
              <p className="text-[11px] text-slate-400">
                Adjust organizational weights to simulate different threat-tolerance postures:
              </p>

              {Object.keys(weights).map((k) => {
                const key = k as keyof RiskWeights;
                return (
                  <div key={k} className="space-y-1">
                    <div className="flex justify-between text-slate-300 text-[11px]">
                      <span className="capitalize">{k.replace(/([A-Z])/g, ' $1')}</span>
                      <span className="font-bold text-cyan-400">
                        {Math.round(weights[key] * 100)}%
                      </span>
                    </div>
                    <input
                      type="range"
                      min="0"
                      max="0.5"
                      step="0.05"
                      value={weights[key]}
                      onChange={(e) => handleWeightChange(key, parseFloat(e.target.value))}
                      className="w-full accent-cyan-400 cursor-pointer"
                    />
                  </div>
                );
              })}

              <div className="pt-2 border-t border-slate-800 flex justify-between text-[11px] text-slate-400">
                <span>Sum of Weights:</span>
                <span className="font-bold text-slate-200">
                  {Math.round(
                    (weights.evidenceStrength +
                      weights.assetCriticality +
                      weights.correlationStrength +
                      weights.threatIntelConfidence +
                      weights.temporalCorrelation) *
                      100
                  )}
                  %
                </span>
              </div>
            </div>
          </Card>

          {/* Explain Score Card */}
          <Card
            title="Explainable Assessment Rationale"
            subtitle="Audit-ready natural language justification"
          >
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 bg-slate-900 border border-slate-800 rounded text-slate-200 leading-relaxed">
                "{explanation}"
              </div>

              <div className="p-2.5 bg-cyan-950/20 border border-cyan-900/40 rounded text-cyan-300 text-[11px]">
                ✓ Verifiable audit trail exported for commander review.
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
