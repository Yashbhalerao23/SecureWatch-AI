import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
}

const variantStyles = {
  primary: 'bg-soc-accent text-slate-950 shadow-lg shadow-soc-accent/20 hover:bg-sky-400 disabled:bg-slate-600 disabled:opacity-50',
  secondary: 'border border-soc-border bg-slate-900/95 text-slate-100 hover:bg-slate-800 disabled:bg-slate-900 disabled:text-slate-500',
  ghost: 'text-slate-300 hover:bg-slate-800/80 disabled:text-slate-600',
  danger: 'bg-red-600/90 text-white hover:bg-red-700 disabled:bg-slate-600 disabled:opacity-50',
};

const sizeStyles = {
  sm: 'rounded-lg px-3 py-1.5 text-xs font-medium',
  md: 'rounded-2xl px-4 py-2 text-sm font-semibold',
  lg: 'rounded-2xl px-6 py-3 text-base font-semibold',
};

export default function Button({
  variant = 'primary',
  size = 'md',
  className,
  ...props
}: ButtonProps) {
  return (
    <button
      className={`transition-colors ${sizeStyles[size]} ${variantStyles[variant]} ${
        className ?? ''
      }`}
      {...props}
    />
  );
}
