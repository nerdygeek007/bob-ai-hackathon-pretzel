import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Bell,
  Layers,
  Globe2,
  Crosshair,
  Database,
  GitCompare,
  SlidersHorizontal,
  Scale,
  FileText,
  Activity,
  HeartPulse,
  Settings,
  Shield,
  RefreshCw,
} from 'lucide-react';
import { useSentinel } from '../../store/sentinelStore';

interface NavItem {
  name: string;
  path: string;
  icon: React.ElementType;
  badge?: number;
}

export const Sidebar: React.FC = () => {
  const { activeSourcesCount, totalSourcesCount, loadDemoData, isDemoMode, alerts, incidents } =
    useSentinel();

  const openIncidentsCount = incidents.filter((i) => i.status !== 'RESOLVED').length;
  const liveAlertsCount = alerts.length;

  const navItems: NavItem[] = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'Live Alerts', path: '/alerts', icon: Bell, badge: liveAlertsCount },
    { name: 'Correlated Incidents', path: '/incidents', icon: Layers, badge: openIncidentsCount },
    { name: 'Threat Intelligence', path: '/threat-intel', icon: Globe2 },
    { name: 'MITRE ATT&CK', path: '/mitre', icon: Crosshair },
    { name: 'Data Sources', path: '/sources', icon: Database },
    { name: 'Normalization', path: '/normalization', icon: GitCompare },
    { name: 'Correlation Rules', path: '/correlation', icon: SlidersHorizontal },
    { name: 'Risk & Priority', path: '/risk', icon: Scale },
    { name: 'BLUF Reports', path: '/bluf', icon: FileText },
    { name: 'Telemetry', path: '/telemetry', icon: Activity },
    { name: 'System Health', path: '/health', icon: HeartPulse },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0d131f] border-r border-[#1e293b] flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#1e293b] flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-mono font-black tracking-wider text-base text-slate-100">
                SENTINEL-X
              </span>
              <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono font-bold">
                SOC
              </span>
            </div>
            <p className="text-[10px] text-slate-400 tracking-tight leading-tight">
              Threat Intel & Prioritisation
            </p>
          </div>
        </div>
      </div>

      {/* Nav list */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center justify-between px-3 py-2 rounded-sm text-xs font-medium font-mono transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-950/70 text-cyan-300 border-l-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <div className="flex items-center gap-2.5">
                <Icon className="w-4 h-4 shrink-0" />
                <span className="truncate">{item.name}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="px-1.5 py-0.2 text-[10px] rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  {item.badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom Status Panel */}
      <div className="p-3.5 bg-[#090d16] border-t border-[#1e293b] space-y-2.5 text-xs font-mono">
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider">System Status</span>
          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]" />
            OPERATIONAL
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider">Mode</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/60 font-bold">
            {isDemoMode ? 'DEMO / SIMULATION' : 'LIVE TELEMETRY'}
          </span>
        </div>

        <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
          <span className="text-[11px] text-slate-400">Active Sources:</span>
          <span className="text-cyan-400 font-bold">
            {activeSourcesCount} / {totalSourcesCount}
          </span>
        </div>

        <button
          onClick={loadDemoData}
          className="w-full mt-1.5 py-1.5 px-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-semibold flex items-center justify-center gap-1.5 transition-colors border border-slate-700 cursor-pointer"
        >
          <RefreshCw className="w-3 h-3 text-cyan-400" />
          LOAD DEMO DATA
        </button>
      </div>
    </aside>
  );
};
