import React from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { RefreshCw, Menu } from 'lucide-react';

interface HeaderProps {
  onOpenMobileNav?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenMobileNav }) => {
  const { isDemoMode, setIsDemoMode, loadDemoData, eventsPerSec } = useSentinel();

  return (
    <header className="h-14 border-b border-[#e5e5e5] bg-white px-4 sm:px-6 flex items-center justify-between sticky top-0 z-20 shrink-0">
      {/* Left: Mobile hamburger + Ingestion indicator */}
      <div className="flex items-center gap-3">
        {/* Mobile Hamburger Toggle Button */}
        {onOpenMobileNav && (
          <button
            onClick={onOpenMobileNav}
            aria-label="Open navigation menu"
            className="md:hidden p-2 -ml-1 rounded-lg text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5] transition-colors cursor-pointer"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}

        {/* Ingestion Status */}
        <div className="flex items-center gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse-subtle" />
            <span className="hidden sm:inline">Live Ingestion</span>
            <span className="sm:hidden">Live</span>
          </span>
          <span className="text-[#e5e5e5] hidden sm:inline">•</span>
          <span className="font-mono text-[11px] text-[#171717] font-medium hidden xs:inline">
            {eventsPerSec.toLocaleString()} <span className="hidden sm:inline">events/sec</span>
          </span>
        </div>
      </div>

      {/* Right: Demo toggle, Reset, User Profile */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* Demo Mode Toggle */}
        <div className="flex items-center gap-2 px-2 py-1 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] text-xs">
          <span className="text-[11px] text-[#737373] hidden sm:inline">Demo</span>
          <button
            onClick={() => setIsDemoMode(!isDemoMode)}
            aria-label="Toggle demo mode"
            className={`w-7 h-4 rounded-full p-0.5 transition-colors cursor-pointer ${
              isDemoMode ? 'bg-blue-600' : 'bg-[#e5e5e5]'
            }`}
          >
            <div
              className={`w-3 h-3 rounded-full bg-white transition-transform ${
                isDemoMode ? 'translate-x-3' : 'translate-x-0'
              }`}
            />
          </button>
        </div>

        {/* Reset Demo Button */}
        <button
          onClick={loadDemoData}
          title="Reset Demo Data"
          className="p-1.5 rounded-lg border border-[#e5e5e5] text-[#737373] hover:text-[#171717] hover:bg-[#f5f5f5] transition-colors cursor-pointer text-xs flex items-center gap-1"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span className="hidden md:inline text-[11px] font-medium">Reset Demo</span>
        </button>

        {/* User profile avatar */}
        <div className="flex items-center gap-2 pl-2 border-l border-[#e5e5e5]">
          <div className="w-7 h-7 rounded-full bg-[#171717] text-white flex items-center justify-center text-xs font-semibold shrink-0">
            SOC
          </div>
          <span className="text-xs font-medium text-[#171717] hidden lg:inline">
            Analyst
          </span>
        </div>
      </div>
    </header>
  );
};
