import React from 'react';
import type { SourceStatus } from '../../types';

interface StatusIndicatorProps {
  status: SourceStatus;
  showLabel?: boolean;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  showLabel = true,
}) => {
  const config = {
    OPERATIONAL: {
      color: 'bg-emerald-400',
      textColor: 'text-emerald-400',
      label: 'OPERATIONAL',
      icon: '●',
    },
    DEGRADED: {
      color: 'bg-amber-400',
      textColor: 'text-amber-400',
      label: 'DEGRADED',
      icon: '◐',
    },
    ERROR: {
      color: 'bg-red-400',
      textColor: 'text-red-400',
      label: 'ERROR',
      icon: '▲',
    },
    DISABLED: {
      color: 'bg-slate-500',
      textColor: 'text-slate-500',
      label: 'DISABLED',
      icon: '○',
    },
  }[status] || {
    color: 'bg-slate-500',
    textColor: 'text-slate-500',
    label: 'UNKNOWN',
    icon: '○',
  };

  return (
    <div className="inline-flex items-center gap-1.5 font-mono text-xs">
      <span className={`w-2 h-2 rounded-full ${config.color} ${status === 'OPERATIONAL' ? 'shadow-[0_0_8px_rgba(52,211,153,0.8)]' : ''}`} />
      {showLabel && <span className={`font-semibold tracking-wider ${config.textColor}`}>{config.label}</span>}
    </div>
  );
};
