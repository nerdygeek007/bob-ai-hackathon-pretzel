import React from 'react';
import { SeverityLevel, PriorityLevel } from '../../types';

interface SeverityBadgeProps {
  severity?: SeverityLevel | PriorityLevel | null;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'source' | 'sentinel';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  variant = 'sentinel',
}) => {
  if (!severity) {
    return (
      <span className="inline-flex items-center text-slate-500 font-mono text-xs px-2 py-0.5 rounded bg-slate-800/60 border border-slate-700/50">
        — Not provided
      </span>
    );
  }

  const styles = {
    CRITICAL: 'bg-red-950/80 text-red-300 border-red-500/40 shadow-sm shadow-red-950',
    HIGH: 'bg-orange-950/80 text-orange-300 border-orange-500/40 shadow-sm shadow-orange-950',
    MEDIUM: 'bg-amber-950/80 text-amber-300 border-amber-500/40 shadow-sm shadow-amber-950',
    LOW: 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40 shadow-sm shadow-emerald-950',
    INFORMATIONAL: 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40',
    UNKNOWN: 'bg-slate-800/80 text-slate-400 border-slate-600/40',
  }[severity] || 'bg-slate-800 text-slate-300 border-slate-700';

  const dotColor = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-amber-500',
    LOW: 'bg-emerald-500',
    INFORMATIONAL: 'bg-cyan-500',
    UNKNOWN: 'bg-slate-500',
  }[severity] || 'bg-slate-400';

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 font-semibold tracking-wider',
    md: 'text-xs px-2.5 py-0.5 font-semibold tracking-wide',
    lg: 'text-sm px-3.5 py-1 font-bold tracking-wider',
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-sm border uppercase font-mono transition-colors ${styles} ${sizeClasses}`}
      title={variant === 'source' ? 'Source Reported Severity' : 'Sentinel-X Computed Priority'}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor} ${severity === 'CRITICAL' ? 'animate-ping' : ''}`} />
      {severity}
    </span>
  );
};
