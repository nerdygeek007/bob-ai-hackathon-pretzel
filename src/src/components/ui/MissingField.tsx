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
      className={`inline-flex items-center text-[#737373] text-xs font-mono group relative cursor-help ${className}`}
      title="Sparse data: Source adapter did not emit this field. Sentinel-X does not fabricate missing values."
    >
      <span className="text-[#a3a3a3] mr-1">—</span>
      <span className="text-[11px] text-[#a3a3a3]">{label}</span>
    </span>
  );
};
