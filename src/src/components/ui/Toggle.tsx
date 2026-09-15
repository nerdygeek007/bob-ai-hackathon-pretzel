import React from 'react';

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  labelOn?: string;
  labelOff?: string;
  disabled?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const Toggle: React.FC<ToggleProps> = ({
  checked,
  onChange,
  labelOn = 'ON',
  labelOff = 'OFF',
  disabled = false,
  size = 'md',
}) => {
  const sizeClasses = {
    sm: {
      btn: 'w-12 h-6 text-[10px]',
      dot: 'w-4 h-4',
      translate: 'translate-x-6',
    },
    md: {
      btn: 'w-16 h-7 text-xs',
      dot: 'w-5 h-5',
      translate: 'translate-x-9',
    },
    lg: {
      btn: 'w-20 h-8 text-sm',
      dot: 'w-6 h-6',
      translate: 'translate-x-12',
    },
  }[size];

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex items-center rounded-full p-1 transition-colors duration-200 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono font-bold select-none ${
        disabled ? 'opacity-40 cursor-not-allowed bg-slate-800' : 'cursor-pointer'
      } ${checked ? 'bg-cyan-600/90 text-white' : 'bg-slate-800 text-slate-400 border border-slate-700'} ${sizeClasses.btn}`}
      role="switch"
      aria-checked={checked}
    >
      <span
        className={`inline-block transform rounded-full bg-white transition-transform duration-200 shadow-md ${sizeClasses.dot} ${
          checked ? sizeClasses.translate : 'translate-x-0'
        }`}
      />
      <span
        className={`absolute text-center uppercase tracking-wider ${
          checked ? 'left-2.5 text-white' : 'right-2.5 text-slate-400'
        }`}
      >
        {checked ? labelOn : labelOff}
      </span>
    </button>
  );
};
