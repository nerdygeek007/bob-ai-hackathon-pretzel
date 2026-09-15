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
      if (value >= 85) return 'bg-red-500';
      if (value >= 65) return 'bg-orange-500';
      if (value >= 40) return 'bg-amber-500';
      return 'bg-emerald-500';
    }
    if (type === 'completeness') {
      return 'bg-neutral-600';
    }
    // confidence
    if (value >= 80) return 'bg-blue-600';
    if (value >= 50) return 'bg-blue-400';
    return 'bg-neutral-400';
  };

  const height = size === 'sm' ? 'h-1.5' : 'h-2';

  return (
    <div className="flex flex-col gap-1.5 w-full">
      <div className="flex items-center justify-between text-xs">
        <span className="text-[#737373] text-[11px] font-medium">{label}</span>
        {showPercent && (
          <span className="font-semibold text-[#171717] font-mono text-xs">
            {value}%
          </span>
        )}
      </div>
      <div className={`w-full bg-[#f5f5f5] rounded-full overflow-hidden border border-[#e5e5e5] ${height}`}>
        <div
          className={`h-full transition-all duration-300 rounded-full ${getBarColor()}`}
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
        />
      </div>
    </div>
  );
};
