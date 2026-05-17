import { useEffect, useState } from 'react';
import { api } from '../lib/axios';
import { AlertItem } from '../types';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import AlertDetailModal from '../components/modals/AlertDetailModal';
import { useRBAC } from '../hooks/useRBAC';

const statusColor: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  new: 'info',
  acknowledged: 'low',
  resolved: 'medium',
  false_positive: 'high'
};

export default function Alerts() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(true);
  const { can } = useRBAC();

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const response = await api.get<{ results: AlertItem[] }>('/alerts/', {
        params: {
          search: search || undefined,
          status: status || undefined
        }
      });
      setAlerts(response.data.results);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [search, status]);

  const handleAction = async (action: 'acknowledge' | 'resolve' | 'false_positive') => {
    if (!selectedAlert) return;

    try {
      await api.post(`/alerts/${selectedAlert.id}/${action}/`);
      await fetchAlerts();
      setSelectedAlert(null);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div className="space-y-6">
      <div className="panel-card p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">Alerts</h2>
            <p className="mt-2 text-sm text-slate-400">Investigate alert priority, threat source, and current status.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <input
              type="search"
              className="rounded-2xl border border-soc-border bg-slate-900/95 px-4 py-3 text-sm text-slate-100 outline-none"
              placeholder="Search alerts"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <select
              className="rounded-2xl border border-soc-border bg-slate-900/95 px-4 py-3 text-sm text-slate-100 outline-none"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              <option value="">Alert status</option>
              <option value="new">New</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False positive</option>
            </select>
          </div>
        </div>
      </div>

      <div className="panel-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full border-separate border-spacing-0 text-sm">
            <thead className="bg-slate-950/95 text-slate-400">
              <tr>
                <th className="px-6 py-4 text-left">Title</th>
                <th className="px-6 py-4 text-left">Severity</th>
                <th className="px-6 py-4 text-left">Source</th>
                <th className="px-6 py-4 text-left">Hostname</th>
                <th className="px-6 py-4 text-left">Created</th>
                <th className="px-6 py-4 text-left">Status</th>
                <th className="px-6 py-4 text-left">AI score</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-slate-500">Loading alerts…</td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-slate-500">No alerts match the filters.</td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.id} className="border-t border-soc-border hover:bg-slate-900/80 cursor-pointer" onClick={() => setSelectedAlert(alert)}>
                    <td className="px-6 py-4 text-slate-200">{alert.title}</td>
                    <td className="px-6 py-4"><Badge variant={alert.severity}>{alert.severity}</Badge></td>
                    <td className="px-6 py-4 text-slate-200">{alert.source}</td>
                    <td className="px-6 py-4 text-slate-200">{alert.hostname}</td>
                    <td className="px-6 py-4 text-slate-200">{alert.created_at}</td>
                    <td className="px-6 py-4"><Badge variant={statusColor[alert.status]}>{alert.status.replace('_', ' ')}</Badge></td>
                    <td className="px-6 py-4 text-slate-200">{alert.ai_score ? `${alert.ai_score}%` : 'TBD'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <AlertDetailModal
        open={Boolean(selectedAlert)}
        alert={selectedAlert ?? undefined}
        onClose={() => setSelectedAlert(null)}
        onAction={handleAction}
        permissions={{
          acknowledge: can('acknowledge_alert'),
          resolve: can('resolve_alert'),
          falsePositive: can('mark_false_positive')
        }}
      />
    </div>
  );
}
