import clsx from 'clsx';

interface BadgeProps {
  variant: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success';
  children: React.ReactNode;
}

const variants = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'bg-slate-800 text-slate-100 border border-slate-700',
  success: 'bg-emerald-600/15 text-emerald-300 border border-emerald-500/30'
};

export default function Badge({ variant, children }: BadgeProps) {
  return <span className={clsx('inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em]', variants[variant])}>{children}</span>;
}
