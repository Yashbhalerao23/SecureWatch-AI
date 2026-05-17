import Badge from '../ui/Badge';

interface MetricCardProps {
  label: string;
  value: string | number;
  description: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success';
}

const severityColors = {
  critical: 'border-red-500/20 bg-red-500/5',
  high: 'border-orange-500/20 bg-orange-500/5',
  medium: 'border-yellow-500/20 bg-yellow-500/5',
  low: 'border-blue-500/20 bg-blue-500/5',
  info: 'border-soc-accent/20 bg-soc-accent/5',
  success: 'border-emerald-500/20 bg-emerald-500/5',
};

export default function MetricCard({ label, value, description, severity = 'info' }: MetricCardProps) {
  return (
    <div className={`panel-card p-5 transition-all hover:scale-[1.02] duration-300 border-b-2 ${severityColors[severity]}`}>
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">{label}</p>
          <p className="text-3xl font-black text-white tabular-nums">{value}</p>
        </div>
        <div className={`h-2 w-2 rounded-full mt-1 ${
          severity === 'critical' ? 'bg-red-500 animate-pulse shadow-[0_0_8px_#ef4444]' : 
          severity === 'high' ? 'bg-orange-500' : 
          severity === 'success' ? 'bg-emerald-500' : 'bg-soc-accent'
        }`} />
      </div>
      <p className="mt-4 text-[11px] leading-relaxed text-slate-400 line-clamp-2 min-h-[32px]">{description}</p>
    </div>
  );
}
