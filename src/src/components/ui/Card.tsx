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
    <div className={`bg-[#111827] border border-[#1f293d] rounded-sm shadow-lg overflow-hidden ${className}`}>
      {(title || headerAction || badge) && (
        <div className="px-4 py-3 bg-gradient-to-r from-slate-900/90 to-slate-900/40 border-b border-[#1f293d] flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            {title && (
              <h3 className="text-sm font-semibold tracking-wide text-slate-100 uppercase font-mono">
                {title}
              </h3>
            )}
            {subtitle && (
              <span className="text-xs text-slate-400 font-normal">
                {subtitle}
              </span>
            )}
            {badge}
          </div>
          {headerAction && <div className="flex items-center gap-2">{headerAction}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-4'}>{children}</div>
    </div>
  );
};
