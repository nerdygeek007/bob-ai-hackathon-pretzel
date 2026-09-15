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
  disabled = false,
  size = 'md',
}) => {
  const sizeClasses = {
    sm: {
      btn: 'w-8 h-4.5 p-0.5',
      dot: 'w-3.5 h-3.5',
      translate: 'translate-x-3.5',
    },
    md: {
      btn: 'w-11 h-6 p-0.5',
      dot: 'w-5 h-5',
      translate: 'translate-x-5',
    },
    lg: {
      btn: 'w-14 h-7 p-0.5',
      dot: 'w-6 h-6',
      translate: 'translate-x-7',
    },
  }[size];

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex shrink-0 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500/20 select-none ${
        disabled ? 'opacity-40 cursor-not-allowed bg-neutral-200' : 'cursor-pointer'
      } ${checked ? 'bg-blue-600' : 'bg-[#e5e5e5]'} ${sizeClasses.btn}`}
      role="switch"
      aria-checked={checked}
    >
      <span
        className={`inline-block transform rounded-full bg-white transition-transform duration-200 shadow-xs ${sizeClasses.dot} ${
          checked ? sizeClasses.translate : 'translate-x-0'
        }`}
      />
    </button>
  );
};
