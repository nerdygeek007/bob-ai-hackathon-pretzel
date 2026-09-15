import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Bell,
  Layers,
  Database,
  Activity,
  Settings,
  Shield,
  X,
} from 'lucide-react';
import { useSentinel } from '../../store/sentinelStore';

interface NavItem {
  name: string;
  path: string;
  icon: React.ElementType;
  badge?: number;
}

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const { alerts, incidents, simulatorRunning } = useSentinel();

  const highPriorityAlertsCount = alerts.filter(
    (a) => a.priority === 'HIGH' || a.priority === 'CRITICAL'
  ).length;
  const activeIncidentsCount = incidents.filter(
    (i) => i.status !== 'RESOLVED' && i.status !== 'CLOSED'
  ).length;

  const navItems: NavItem[] = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'Alerts', path: '/alerts', icon: Bell, badge: highPriorityAlertsCount },
    { name: 'Incidents', path: '/incidents', icon: Layers, badge: activeIncidentsCount },
    { name: 'Data Sources', path: '/sources', icon: Database },
    { name: 'Simulator', path: '/simulator', icon: Activity },
  ];

  const handleLinkClick = () => {
    if (onClose) {
      onClose();
    }
  };

  const navContent = (
    <div className="flex flex-col h-full bg-white select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#e5e5e5] flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#000000] text-white flex items-center justify-center shadow-xs shrink-0">
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-semibold text-sm tracking-tight text-[#171717]">
                Sentinel-X
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-blue-50 text-blue-700 font-medium border border-blue-200/60">
                SaaS
              </span>
            </div>
            <p className="text-[11px] text-[#737373] leading-none mt-0.5">
              Threat Intelligence Assistant
            </p>
          </div>
        </div>

        {/* Mobile close button */}
        {onClose && (
          <button
            onClick={onClose}
            aria-label="Close menu"
            className="md:hidden p-1.5 rounded-lg hover:bg-[#f5f5f5] text-[#737373] hover:text-[#171717] transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Primary Navigation */}
      <div className="p-3">
        <span className="px-3 text-[11px] font-medium uppercase tracking-wider text-[#737373]/80">
          Platform
        </span>
      </div>
      <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={handleLinkClick}
              className={({ isActive }) =>
                `flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-[#f5f5f5] text-[#171717] font-semibold'
                    : 'text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5]/60'
                }`
              }
            >
              <div className="flex items-center gap-2.5">
                <Icon className="w-4 h-4 shrink-0 text-[#737373]" />
                <span>{item.name}</span>
              </div>
              {item.path === '/simulator' && simulatorRunning && (
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
              )}
              {item.badge !== undefined && item.badge > 0 && item.path !== '/simulator' && (
                <span className="px-2 py-0.2 text-[10px] rounded-full font-medium bg-[#f5f5f5] text-[#171717] border border-[#e5e5e5]">
                  {item.badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom Section: Settings & Status */}
      <div className="p-3 border-t border-[#e5e5e5] space-y-1">
        <NavLink
          to="/settings"
          onClick={handleLinkClick}
          className={({ isActive }) =>
            `flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
              isActive
                ? 'bg-[#f5f5f5] text-[#171717] font-semibold'
                : 'text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5]/60'
            }`
          }
        >
          <Settings className="w-4 h-4 text-[#737373]" />
          <span>Settings</span>
        </NavLink>

        {/* Pipeline Status Indicator */}
        <div className="mt-2 p-2.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-[#737373]">Pipeline</span>
            <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-emerald-700">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse-subtle" />
              Operational
            </span>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* 1. Desktop Fixed Sidebar */}
      <aside className="hidden md:flex md:w-60 h-screen border-r border-[#e5e5e5] bg-white flex-col select-none shrink-0">
        {navContent}
      </aside>

      {/* 2. Mobile Drawer Navigation */}
      {isOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity duration-300"
            onClick={onClose}
          />

          {/* Drawer Sidebar */}
          <div className="relative w-72 max-w-[85vw] bg-white h-full shadow-2xl z-10 flex flex-col border-r border-[#e5e5e5] animate-in slide-in-from-left duration-200">
            {navContent}
          </div>
        </div>
      )}
    </>
  );
};
