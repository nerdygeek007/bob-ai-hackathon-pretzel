import React from 'react';

interface RiskGaugeProps {
  score: number; // 0-100
  size?: number; // width/height in px
  showLabel?: boolean;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 100,
  showLabel = true,
}) => {
  const strokeWidth = 7;
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
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="transform -rotate-90" width={size} height={size}>
          {/* Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#e5e5e5"
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
            className="transition-all duration-500 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold font-mono text-[#171717]">{score}</span>
          <span className="text-[10px] text-[#737373] font-medium">/ 100</span>
        </div>
      </div>
      {showLabel && (
        <span className="text-[11px] text-[#737373] mt-1 font-medium">
          Risk Score
        </span>
      )}
    </div>
  );
};
