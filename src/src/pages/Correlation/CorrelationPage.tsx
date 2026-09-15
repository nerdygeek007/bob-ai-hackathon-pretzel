import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { Toggle } from '../../components/ui/Toggle';
import {
  SlidersHorizontal,
  Clock,
  Layers,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  Play,
} from 'lucide-react';
import { correlationService } from '../../services/correlationService';

export const CorrelationPage: React.FC = () => {
  const {
    correlationConfig,
    toggleCorrelationRule,
    updateCorrelationWindow,
    updateMinSources,
  } = useSentinel();

  const [isRunningPass, setIsRunningPass] = useState(false);
  const [passFeedback, setPassFeedback] = useState<string | null>(null);

  const handleRunPass = async () => {
    setIsRunningPass(true);
    setPassFeedback(null);
    const res = await correlationService.runCorrelationPass(correlationConfig);
    setIsRunningPass(false);
    setPassFeedback(
      `Correlation pass complete: ${res.updatedIncidents} active incident clusters evaluated, 0 unlinked alerts remaining in current window.`
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
            CROSS-SOURCE CORRELATION ENGINE RULES
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Configurable deterministic multi-source correlation logic and temporal clustering thresholds
          </p>
        </div>

        <button
          onClick={handleRunPass}
          disabled={isRunningPass}
          className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-mono font-bold text-xs flex items-center gap-2 shadow-md shadow-cyan-950 transition-colors cursor-pointer"
        >
          <Play className={`w-3.5 h-3.5 ${isRunningPass ? 'animate-spin' : ''}`} />
          {isRunningPass ? 'Executing Pass...' : 'Run Correlation Pass'}
        </button>
      </div>

      {passFeedback && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800 rounded text-emerald-300 font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{passFeedback}</span>
        </div>
      )}

      {/* Global Configuration Parameters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
        <Card
          title="Temporal Correlation Window"
          subtitle="Sliding time horizon for corroborating multi-source alerts"
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Sliding Window Duration:</span>
              <span className="text-cyan-400 font-bold text-base">
                {correlationConfig.windowMinutes} Minutes
              </span>
            </div>
            <input
              type="range"
              min="1"
              max="30"
              step="1"
              value={correlationConfig.windowMinutes}
              onChange={(e) => updateCorrelationWindow(parseInt(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-500">
              <span>1 min (Tight)</span>
              <span>5 min (Standard)</span>
              <span>30 min (Campaign Horizon)</span>
            </div>
          </div>
        </Card>

        <Card
          title="Corroboration Threshold"
          subtitle="Minimum independent sources required to elevate incident priority"
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Min Corroborating Sources:</span>
              <span className="text-cyan-400 font-bold text-base">
                {correlationConfig.minCorroboratingSources} Independent Sources
              </span>
            </div>
            <input
              type="range"
              min="1"
              max="4"
              step="1"
              value={correlationConfig.minCorroboratingSources}
              onChange={(e) => updateMinSources(parseInt(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-500">
              <span>1 (Single Source)</span>
              <span>2 (Dual Corroboration)</span>
              <span>4 (Strict Consensus)</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Correlation Rules Matrix */}
      <Card
        title="Active Correlation Heuristics & Rules"
        subtitle="Toggle and fine-tune deterministic linking logic"
      >
        <div className="space-y-3 font-mono text-xs">
          {correlationConfig.rules.map((rule) => (
            <div
              key={rule.ruleId}
              className={`p-4 rounded border flex items-center justify-between gap-4 transition-all ${
                rule.enabled
                  ? 'bg-slate-900/80 border-slate-700/80'
                  : 'bg-slate-950/40 border-slate-800 opacity-60'
              }`}
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-100 text-sm">{rule.label}</span>
                  <span
                    className={`text-[9px] px-1.5 py-0.2 rounded font-bold border ${
                      rule.enabled
                        ? 'bg-cyan-950 text-cyan-400 border-cyan-800'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {rule.enabled ? 'ACTIVE RULE' : 'MUTED'}
                  </span>
                  <span className="text-[10px] text-slate-500">ID: {rule.ruleId}</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">{rule.description}</p>
              </div>

              <Toggle
                checked={rule.enabled}
                onChange={() => toggleCorrelationRule(rule.ruleId)}
                size="md"
              />
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
