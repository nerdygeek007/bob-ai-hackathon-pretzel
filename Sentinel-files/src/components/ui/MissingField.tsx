import React from 'react';

interface MissingFieldProps {
  label?: string;
  className?: string;
}

export const MissingField: React.FC<MissingFieldProps> = ({
  label = 'Not provided',
  className = '',
}) => {
  return (
    <span
      className={`inline-flex items-center text-slate-500 font-mono text-xs italic group relative cursor-help ${className}`}
      title="Sparse data: Source adapter did not emit this field. Never fabricated."
    >
      <span className="text-slate-500 font-bold mr-1">—</span>
      <span className="text-[11px] text-slate-500/80">{label}</span>
    </span>
  );
};
