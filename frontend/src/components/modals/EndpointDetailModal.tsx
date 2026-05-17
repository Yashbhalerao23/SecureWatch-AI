import { useState, useEffect } from 'react';
import { api } from '../../lib/axios';
import Dialog from '../ui/Dialog';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import Spinner from '../ui/Spinner';
import { AlertItem, LogEvent } from '../../types';

export interface EndpointDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  endpointId: number | null;
  hostname: string;
}

const EndpointDetailModal: React.FC<EndpointDetailModalProps> = ({
  open,
  onOpenChange,
  endpointId,
  hostname,
}) => {
  const [loading, setLoading] = useState(false);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [activeTab, setActiveTab] = useState<'alerts' | 'logs'>('alerts');

  useEffect(() => {
    if (open && endpointId) {
      fetchEndpointDetails();
    }
  }, [open, endpointId]);

  const fetchEndpointDetails = async () => {
    if (!endpointId) return;
    setLoading(true);
    try {
      const [alertsRes, logsRes] = await Promise.all([
        api.get<AlertItem[]>(`/alerts/?hostname=${hostname}&limit=10`),
        api.get<LogEvent[]>(`/logs/?hostname=${hostname}&limit=10`),
      ]);
      setAlerts(alertsRes.data);
      setLogs(logsRes.data);
    } catch (error) {
      console.error('Failed to fetch endpoint details:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Endpoint: ${hostname}`}
      description="Recent activity and security status"
      size="lg"
      footer={
        <div className="flex gap-3 justify-end">
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button variant="secondary">Isolate Endpoint</Button>
        </div>
      }
    >
      <div className="space-y-4">
        {/* Tab Navigation */}
        <div className="flex gap-2 border-b border-soc-border">
          <button
            onClick={() => setActiveTab('alerts')}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === 'alerts'
                ? 'border-b-2 border-soc-accent text-white'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Recent Alerts ({alerts.length})
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === 'logs'
                ? 'border-b-2 border-soc-accent text-white'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Recent Logs ({logs.length})
          </button>
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex justify-center py-8">
            <Spinner size="md" text="Loading endpoint details..." />
          </div>
        ) : activeTab === 'alerts' ? (
          <div className="space-y-2">
            {alerts.length === 0 ? (
              <p className="text-sm text-slate-400 py-4">No recent alerts</p>
            ) : (
              alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="rounded-2xl border border-soc-border bg-slate-900/50 p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium text-slate-200">{alert.title}</p>
                    <Badge variant={alert.severity}>{alert.severity}</Badge>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{alert.source}</p>
                </div>
              ))
            )}
          </div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {logs.length === 0 ? (
              <p className="text-sm text-slate-400 py-4">No recent logs</p>
            ) : (
              logs.map((log) => (
                <div
                  key={log.id}
                  className="rounded-2xl border border-soc-border bg-slate-900/50 p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <p className="text-xs text-slate-400">Event ID: {log.event_id}</p>
                      <p className="text-sm text-slate-200 mt-1">{log.message.substring(0, 60)}</p>
                    </div>
                    <Badge variant={log.severity}>{log.severity}</Badge>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </Dialog>
  );
};

export default EndpointDetailModal;
