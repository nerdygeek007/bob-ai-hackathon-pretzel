import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { Toggle } from '../../components/ui/Toggle';
import { RefreshCw, Database, Shield, Sliders, CheckCircle2 } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { loadDemoData, isDemoMode, setIsDemoMode, correlationConfig, updateCorrelationWindow } = useSentinel();
  const [retentionDays, setRetentionDays] = useState(30);
  const [autoPurgeRaw, setAutoPurgeRaw] = useState(false);
  const [savedNotice, setSavedNotice] = useState(false);

  const handleSave = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-4xl pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#171717]">
          Settings
        </h1>
        <p className="text-sm text-[#737373] mt-0.5">
          Organization policies, correlation rules, and demonstration preferences
        </p>
      </div>

      {savedNotice && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-emerald-900 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>Platform configuration updated successfully.</span>
        </div>
      )}

      {/* Demo / Simulation Mode Management */}
      <Card
        title="Demonstration Mode"
        subtitle="Manage synthetic data feeds and scenario playback"
      >
        <div className="space-y-4 text-xs">
          <div className="flex items-center justify-between p-3.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
            <div>
              <span className="font-semibold text-sm text-[#171717] block">
                Enable Demo Simulation
              </span>
              <span className="text-xs text-[#737373] mt-0.5 block">
                Populates mock scenarios (OTRF Mordor, NASA JPL, CIC-IDS) without connecting live sensors
              </span>
            </div>
            <Toggle checked={isDemoMode} onChange={setIsDemoMode} size="sm" />
          </div>

          <div className="pt-2 flex items-center gap-3">
            <button
              onClick={loadDemoData}
              className="px-3.5 py-2 rounded-lg bg-[#000000] hover:bg-neutral-800 text-white font-medium text-xs flex items-center gap-2 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Reset Demo Dataset
            </button>
            <span className="text-[11px] text-[#737373]">
              Restores initial incidents, telemetry, and alerts
            </span>
          </div>
        </div>
      </Card>

      {/* Correlation & Risk Engine Configuration */}
      <Card
        title="Correlation Proximity & Risk Engine"
        subtitle="Application correlation policies and temporal windows"
      >
        <div className="space-y-4 text-xs">
          <div>
            <label className="block text-[#737373] text-[11px] font-medium mb-1">
              Temporal Proximity Window (Minutes)
            </label>
            <input
              type="number"
              value={correlationConfig.windowMinutes}
              onChange={(e) => updateCorrelationWindow(parseInt(e.target.value) || 15)}
              className="w-48 bg-white border border-[#e5e5e5] rounded-md px-3 py-1.5 text-xs text-[#171717] focus:outline-none focus:border-blue-600"
            />
            <p className="text-[11px] text-[#737373] mt-1">
              Events occurring on the same asset within this window are evaluated for multi-stage correlation.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] space-y-2">
            <span className="font-semibold text-xs text-[#171717] block">Active Correlation Rules</span>
            <div className="space-y-2">
              {correlationConfig.rules.map((rule) => (
                <div key={rule.ruleId} className="flex items-center justify-between text-xs py-1">
                  <div>
                    <span className="font-medium text-[#171717]">{rule.label}</span>
                    <p className="text-[11px] text-[#737373]">{rule.description}</p>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 font-medium border border-blue-200">
                    Enforced
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Storage & Data Retention Settings */}
      <Card
        title="Data Retention & Provenance"
        subtitle="Raw forensic log caching and canonical event storage"
      >
        <div className="space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[#737373] text-[11px] font-medium mb-1">
                Raw Evidence Retention (Days)
              </label>
              <input
                type="number"
                value={retentionDays}
                onChange={(e) => setRetentionDays(parseInt(e.target.value) || 30)}
                className="w-full bg-white border border-[#e5e5e5] rounded-md px-3 py-1.5 text-xs text-[#171717] focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          <div className="flex items-center justify-between p-3.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
            <div>
              <span className="font-medium text-xs text-[#171717] block">
                Auto-Purge Raw Payloads on Resolution
              </span>
              <span className="text-[11px] text-[#737373] mt-0.5 block">
                Retains canonical events while pruning heavy raw pcap and evtx attachments
              </span>
            </div>
            <Toggle checked={autoPurgeRaw} onChange={setAutoPurgeRaw} size="sm" />
          </div>

          <div className="pt-2">
            <button
              onClick={handleSave}
              className="px-4 py-2 rounded-lg bg-[#000000] text-white hover:bg-neutral-800 text-xs font-medium transition-colors cursor-pointer"
            >
              Save Changes
            </button>
          </div>
        </div>
      </Card>
    </div>
  );
};
