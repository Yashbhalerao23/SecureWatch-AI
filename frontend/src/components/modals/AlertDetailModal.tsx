import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { AlertItem } from '../../types';

interface AlertDetailModalProps {
  open: boolean;
  alert?: AlertItem;
  onClose: () => void;
  onAction: (action: 'acknowledge' | 'resolve' | 'false_positive') => void;
  permissions?: {
    acknowledge: boolean;
    resolve: boolean;
    falsePositive: boolean;
  };
}

const statusMap = {
  new: 'info',
  acknowledged: 'low',
  resolved: 'medium',
  false_positive: 'high'
} as const;

export default function AlertDetailModal({ open, alert, onClose, onAction, permissions }: AlertDetailModalProps) {
  if (!open || !alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/70 px-4 py-8 sm:items-center">
      <div className="w-full max-w-3xl rounded-3xl border border-soc-border bg-slate-950/95 p-6 shadow-panel">
        <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Alert detail</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">{alert.title}</h3>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Badge variant={alert.severity}>{alert.severity}</Badge>
            <Badge variant={statusMap[alert.status]}>{alert.status.replace('_', ' ')}</Badge>
            <Button variant="ghost" onClick={onClose}>Close</Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-3xl border border-soc-border bg-slate-900/95 p-4">
            <p className="text-sm text-slate-400">Source</p>
            <p className="mt-2 text-sm text-slate-100">{alert.source}</p>
            <p className="mt-4 text-sm text-slate-400">Hostname</p>
            <p className="mt-2 text-sm text-slate-100">{alert.hostname}</p>
            <p className="mt-4 text-sm text-slate-400">Event ID</p>
            <p className="mt-2 text-sm text-slate-100">{alert.event_id ?? 'N/A'}</p>
          </div>
          <div className="rounded-3xl border border-soc-border bg-slate-900/95 p-4">
            <p className="text-sm text-slate-400">Created</p>
            <p className="mt-2 text-sm text-slate-100">{alert.created_at}</p>
            <p className="mt-4 text-sm text-slate-400">AI Score</p>
            <p className="mt-2 text-sm text-slate-100">{alert.ai_score != null ? `${alert.ai_score}%` : 'Unknown'}</p>
          </div>
        </div>

        {(permissions?.acknowledge || permissions?.resolve || permissions?.falsePositive) && (
          <div className="mt-6 flex flex-wrap gap-3">
            {permissions?.acknowledge && (
              <Button variant="secondary" onClick={() => onAction('acknowledge')}>Acknowledge</Button>
            )}
            {permissions?.resolve && (
              <Button variant="secondary" onClick={() => onAction('resolve')}>Resolve</Button>
            )}
            {permissions?.falsePositive && (
              <Button variant="secondary" onClick={() => onAction('false_positive')}>False Positive</Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
