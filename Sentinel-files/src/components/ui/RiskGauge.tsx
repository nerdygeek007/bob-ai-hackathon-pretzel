import React from 'react';

interface RiskGaugeProps {
  score: number; // 0-100
  size?: number; // width/height in px
  showLabel?: boolean;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 110,
  showLabel = true,
}) => {
  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const getColor = () => {
    if (score >= 85) return '#ef4444'; // critical red
    if (score >= 65) return '#f97316'; // high orange
    if (score >= 40) return '#f59e0b'; // medium amber
    return '#10b981'; // low emerald
  };

  return (
    <div className="flex flex-col items-center justify-center font-mono">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="transform -rotate-90" width={size} height={size}>
          {/* Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={getColor()}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-black text-slate-100">{score}</span>
          <span className="text-[9px] uppercase tracking-wider text-slate-400">/ 100</span>
        </div>
      </div>
      {showLabel && (
        <span className="text-[10px] text-slate-400 mt-1 uppercase tracking-widest font-semibold">
          Risk Score
        </span>
      )}
    </div>
  );
};
