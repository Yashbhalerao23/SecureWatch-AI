import React from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className = '', label, error, icon, ...props }, ref) => {
    return (
      <div className="flex flex-col gap-1">
        {label && (
          <label className="text-sm font-medium text-slate-300">
            {label}
            {props.required && <span className="text-red-400 ml-1">*</span>}
          </label>
        )}
        <div className="relative flex items-center">
          {icon && <div className="absolute left-3 text-slate-400">{icon}</div>}
          <input
            ref={ref}
            className={`w-full rounded-2xl border border-soc-border bg-slate-900/95 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 outline-none transition-colors focus:border-soc-accent focus:ring-1 focus:ring-soc-accent ${
              icon ? 'pl-10' : ''
            } ${error ? 'border-red-500' : ''} ${className}`}
            {...props}
          />
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
      </div>
    );
  }
);

Input.displayName = 'Input';

export default Input;
