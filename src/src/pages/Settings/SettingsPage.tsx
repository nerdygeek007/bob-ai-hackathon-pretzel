import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { Toggle } from '../../components/ui/Toggle';
import { RefreshCw, Database, Shield, Sliders, CheckCircle2 } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { loadDemoData, isDemoMode } = useSentinel();
  const [retentionDays, setRetentionDays] = useState(30);
  const [streamBufferMb, setStreamBufferMb] = useState(256);
  const [autoPurgeRaw, setAutoPurgeRaw] = useState(false);
  const [savedNotice, setSavedNotice] = useState(false);

  const handleSave = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          COMMAND PLATFORM SETTINGS & SIMULATION
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          System telemetry storage, demo data reload, and platform pipeline parameters
        </p>
      </div>

      {savedNotice && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800 rounded text-emerald-300 font-mono text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>Platform settings updated and synchronized to SOC configuration store.</span>
        </div>
      )}

      {/* SECTION 29: DEMO / SIMULATION MODE RESET */}
      <Card
        title="Demo / Simulation Mode Management"
        subtitle="Reset and populate synthetic data representing actual public sources"
      >
        <div className="space-y-4 font-mono text-xs">
          <p className="text-slate-300">
            Sentinel-X contains realistic synthetic datasets reflecting OTRF Mordor, EVTX samples,
            CIC-CSE-IDS2018, ET-Open, NASA JPL Telemanom, and OpenSky RF sensors:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
              <span className="text-cyan-400 font-bold block">✓ Genuine Correlated Threat</span>
              <span className="text-slate-400">INC-0042 (SERVER-07, multi-source corroboration)</span>
            </div>
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
              <span className="text-emerald-400 font-bold block">✓ Verified False Positive</span>
              <span className="text-slate-400">INC-0043 (WORKSTATION-14, single weak scan)</span>
            </div>
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
              <span className="text-orange-400 font-bold block">✓ Space Telemetry Anomaly</span>
              <span className="text-slate-400">INC-0044 (SPACECRAFT-M-7 + Uplink Attempt)</span>
            </div>
            <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
              <span className="text-purple-400 font-bold block">✓ CISA KEV & MITRE Enrichment</span>
              <span className="text-slate-400">PrintNightmare CVE match & APT29 TTP mapping</span>
            </div>
          </div>

          <div className="pt-2">
            <button
              onClick={loadDemoData}
              className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-bold text-xs flex items-center gap-2 shadow-md shadow-cyan-950 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Reload Fresh Demo Dataset
            </button>
          </div>
        </div>
      </Card>

      {/* Storage & Retention Settings */}
      <Card title="Raw Evidence Storage & Telemetry Buffers" subtitle="Pipeline retention controls">
        <div className="space-y-4 font-mono text-xs">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 text-[11px] uppercase mb-1">
                Raw Evidence Retention (Days)
              </label>
              <input
                type="number"
                value={retentionDays}
                onChange={(e) => setRetentionDays(parseInt(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
              />
            </div>
            <div>
              <label className="block text-slate-400 text-[11px] uppercase mb-1">
                Stream Memory Buffer (MB)
              </label>
              <input
                type="number"
                value={streamBufferMb}
                onChange={(e) => setStreamBufferMb(parseInt(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200"
              />
            </div>
          </div>

          <div className="flex items-center justify-between p-3 bg-slate-900 rounded border border-slate-800">
            <div>
              <span className="text-slate-200 font-bold block">
                Auto-Purge Raw Payloads on Resolution
              </span>
              <span className="text-[11px] text-slate-400 block mt-0.5">
                Keep canonical events and provenance hash while pruning bulky raw log payloads
              </span>
            </div>
            <Toggle checked={autoPurgeRaw} onChange={setAutoPurgeRaw} size="sm" />
          </div>

          <div className="pt-2">
            <button
              onClick={handleSave}
              className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono font-bold text-xs border border-slate-700 transition-colors cursor-pointer"
            >
              Save Platform Configuration
            </button>
          </div>
        </div>
      </Card>
    </div>
  );
};
