import React from 'react';

interface MetricMeterProps {
  value: number; // 0 - 100
  label: string;
  type?: 'confidence' | 'completeness' | 'risk';
  showPercent?: boolean;
  size?: 'sm' | 'md';
}

export const ConfidenceMeter: React.FC<MetricMeterProps> = ({
  value,
  label,
  type = 'confidence',
  showPercent = true,
  size = 'md',
}) => {
  const getBarColor = () => {
    if (type === 'risk') {
      if (value >= 85) return 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]';
      if (value >= 65) return 'bg-orange-500';
      if (value >= 40) return 'bg-amber-500';
      return 'bg-emerald-500';
    }
    if (type === 'completeness') {
      return 'bg-blue-400';
    }
    // confidence
    if (value >= 80) return 'bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.4)]';
    if (value >= 50) return 'bg-sky-500';
    return 'bg-slate-500';
  };

  const height = size === 'sm' ? 'h-1.5' : 'h-2';

  return (
    <div className="flex flex-col gap-1 w-full font-mono">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-400 text-[11px] uppercase tracking-wider">{label}</span>
        {showPercent && (
          <span className="font-bold text-slate-200">
            {value}%
          </span>
        )}
      </div>
      <div className={`w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700/50 ${height}`}>
        <div
          className={`h-full transition-all duration-500 rounded-full ${getBarColor()}`}
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
        />
      </div>
    </div>
  );
};
