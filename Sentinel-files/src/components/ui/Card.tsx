import React, { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  badge?: ReactNode;
  headerAction?: ReactNode;
  className?: string;
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  title,
  subtitle,
  badge,
  headerAction,
  className = '',
  noPadding = false,
}) => {
  return (
    <div className={`bg-white border border-[#e5e5e5] rounded-xl shadow-[0_1px_3px_rgba(0,0,0,0.02)] overflow-hidden transition-all ${className}`}>
      {(title || headerAction || badge) && (
        <div className="px-5 py-4 border-b border-[#e5e5e5] flex items-center justify-between gap-3 bg-white">
          <div className="flex items-center gap-3">
            <div>
              {title && (
                <h3 className="text-sm font-semibold text-[#171717] tracking-tight">
                  {title}
                </h3>
              )}
              {subtitle && (
                <p className="text-xs text-[#737373] mt-0.5">
                  {subtitle}
                </p>
              )}
            </div>
            {badge}
          </div>
          {headerAction && <div className="flex items-center gap-2">{headerAction}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-5'}>{children}</div>
    </div>
  );
};
