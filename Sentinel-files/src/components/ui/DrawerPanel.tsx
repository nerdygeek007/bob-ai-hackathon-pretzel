import React, { ReactNode } from 'react';
import { X } from 'lucide-react';

interface DrawerPanelProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  width?: string;
}

export const DrawerPanel: React.FC<DrawerPanelProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  width = 'max-w-xl',
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Drawer content */}
      <div
        className={`relative w-full ${width} bg-[#0f172a] border-l border-[#1e293b] shadow-2xl flex flex-col h-full z-10 transition-transform duration-300 ease-in-out`}
      >
        {/* Header */}
        <div className="p-4 bg-slate-900 border-b border-[#1e293b] flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold font-mono uppercase tracking-wide text-slate-100 flex items-center gap-2">
              {title}
            </h2>
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">{children}</div>
      </div>
    </div>
  );
};
