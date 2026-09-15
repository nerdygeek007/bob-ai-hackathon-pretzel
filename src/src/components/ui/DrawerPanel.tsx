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
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Drawer content: Full width on mobile, max-w on tablet/desktop */}
      <div
        className={`relative w-full sm:${width} bg-white border-l border-[#e5e5e5] shadow-2xl flex flex-col h-full z-10 transition-transform duration-300 ease-in-out`}
      >
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-[#e5e5e5] flex items-center justify-between bg-white shrink-0">
          <div className="pr-2 truncate">
            <h2 className="text-base font-semibold text-[#171717] tracking-tight truncate">
              {title}
            </h2>
            {subtitle && <p className="text-xs text-[#737373] mt-0.5 truncate">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            aria-label="Close panel"
            className="p-2 rounded-lg hover:bg-[#f5f5f5] text-[#737373] hover:text-[#171717] transition-colors cursor-pointer shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body with responsive padding */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-5 sm:space-y-6">{children}</div>
      </div>
    </div>
  );
};
