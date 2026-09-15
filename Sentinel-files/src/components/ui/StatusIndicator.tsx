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
      color: 'bg-emerald-500',
      textColor: 'text-emerald-700',
      label: 'Connected',
    },
    DEGRADED: {
      color: 'bg-amber-500',
      textColor: 'text-amber-700',
      label: 'Degraded',
    },
    ERROR: {
      color: 'bg-red-500',
      textColor: 'text-red-700',
      label: 'Error',
    },
    DISABLED: {
      color: 'bg-neutral-400',
      textColor: 'text-neutral-500',
      label: 'Disabled',
    },
  }[status] || {
    color: 'bg-neutral-400',
    textColor: 'text-neutral-500',
    label: 'Unknown',
  };

  return (
    <div className="inline-flex items-center gap-1.5 text-xs">
      <span className={`w-2 h-2 rounded-full ${config.color} ${status === 'OPERATIONAL' ? 'animate-pulse-subtle' : ''}`} />
      {showLabel && <span className={`font-medium ${config.textColor}`}>{config.label}</span>}
    </div>
  );
};
