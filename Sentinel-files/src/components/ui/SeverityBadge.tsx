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
      <span className="inline-flex items-center text-[#737373] text-xs px-2.5 py-0.5 rounded-full bg-[#f5f5f5] border border-[#e5e5e5]">
        — Not provided
      </span>
    );
  }

  const styles = {
    CRITICAL: 'bg-red-50 text-red-700 border-red-200',
    HIGH: 'bg-orange-50 text-orange-700 border-orange-200',
    MEDIUM: 'bg-amber-50 text-amber-800 border-amber-200',
    LOW: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    INFORMATIONAL: 'bg-blue-50 text-blue-700 border-blue-200',
    UNKNOWN: 'bg-neutral-100 text-neutral-600 border-neutral-200',
  }[severity] || 'bg-neutral-100 text-neutral-700 border-neutral-200';

  const dotColor = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-amber-500',
    LOW: 'bg-emerald-500',
    INFORMATIONAL: 'bg-blue-500',
    UNKNOWN: 'bg-neutral-400',
  }[severity] || 'bg-neutral-400';

  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5 font-medium tracking-wide',
    md: 'text-xs px-2.5 py-0.5 font-medium tracking-wide',
    lg: 'text-sm px-3 py-1 font-semibold tracking-wide',
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border transition-colors ${styles} ${sizeClasses}`}
      title={variant === 'source' ? 'Source Reported Severity' : 'Sentinel-X Assessed Priority'}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor} ${severity === 'CRITICAL' ? 'animate-pulse' : ''}`} />
      <span>{severity}</span>
    </span>
  );
};
