import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/axios';
import { LogEvent } from '../types';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Select from '../components/ui/Select';
import Pagination from '../components/ui/Pagination';
import LogDetailModal from '../components/modals/LogDetailModal';
import Spinner from '../components/ui/Spinner';
import { useSocRealtime } from '../hooks/useSocRealtime';

const severityStyles = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
} as const;

export default function Logs() {
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [selectedLog, setSelectedLog] = useState<LogEvent | null>(null);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [eventId, setEventId] = useState('');
  const [source, setSource] = useState('');
  const [hostname, setHostname] = useState('');
  const [user, setUser] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get<{ results: LogEvent[]; count: number }>('/logs/', {
        params: {
          search: query,
          event_id: eventId || undefined,
          severity: severity || undefined,
          source: source || undefined,
          hostname: hostname || undefined,
          user: user || undefined,
          date_from: dateFrom || undefined,
          date_to: dateTo || undefined,
          page,
          page_size: pageSize,
        },
      });
      setLogs(response.data.results);
      setTotalCount(response.data.count);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [query, eventId, severity, source, hostname, user, dateFrom, dateTo, page, pageSize]);

  useEffect(() => {
    void fetchLogs();
  }, [fetchLogs]);

  const { connected } = useSocRealtime(
    useCallback((message) => {
      if (message.type === 'log.ingested') {
        void fetchLogs();
      }
    }, [fetchLogs]),
    ['logs']
  );

  return (
    <div className="space-y-6">
      <div className="panel-card p-6">
        <h2 className="text-xl font-semibold text-white">Log Explorer</h2>
        <p className="mt-2 text-sm text-slate-400">
          Search, filter, and inspect raw event stream data from Windows log collection.
        </p>

        <div className="mt-6 grid gap-4 lg:grid-cols-4">
          <Input
            placeholder="Keyword search"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
          />
          <Input
            placeholder="Event ID"
            value={eventId}
            onChange={(event) => {
              setEventId(event.target.value);
              setPage(1);
            }}
          />
          <Select
            options={[
              { value: '', label: 'All Severity' },
              { value: 'critical', label: 'Critical' },
              { value: 'high', label: 'High' },
              { value: 'medium', label: 'Medium' },
              { value: 'low', label: 'Low' },
            ]}
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              setPage(1);
            }}
          />
          <Input
            placeholder="Source"
            value={source}
            onChange={(event) => {
              setSource(event.target.value);
              setPage(1);
            }}
          />
          <Input
            placeholder="Hostname"
            value={hostname}
            onChange={(event) => {
              setHostname(event.target.value);
              setPage(1);
            }}
          />
          <Input
            placeholder="User"
            value={user}
            onChange={(event) => {
              setUser(event.target.value);
              setPage(1);
            }}
          />
          <Input
            type="datetime-local"
            value={dateFrom}
            onChange={(event) => {
              setDateFrom(event.target.value);
              setPage(1);
            }}
          />
          <Input
            type="datetime-local"
            value={dateTo}
            onChange={(event) => {
              setDateTo(event.target.value);
              setPage(1);
            }}
          />
          <Button variant="secondary" onClick={() => setPage(1)}>
            Search
          </Button>
          <Button variant="ghost" onClick={() => {
            setQuery('');
            setEventId('');
            setSeverity('');
            setSource('');
            setHostname('');
            setUser('');
            setDateFrom('');
            setDateTo('');
            setPage(1);
          }}>Clear</Button>
        </div>
      </div>

      {/* Table */}
      <div className="panel-card overflow-hidden">
        <div className="border-b border-soc-border bg-slate-950/95 px-6 py-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Event stream</h3>
            <div className="text-sm text-slate-400">
              {connected ? 'Live websocket connected' : 'Live websocket offline'} / Total: <span className="font-semibold text-slate-200">{totalCount}</span>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="flex justify-center py-10">
              <Spinner size="md" text="Loading logs..." />
            </div>
          ) : logs.length === 0 ? (
            <div className="px-6 py-10 text-center text-slate-500">No logs found for the current filters.</div>
          ) : (
            <table className="min-w-full border-separate border-spacing-0 text-sm">
              <thead className="bg-slate-950/95 text-slate-400">
                <tr>
                  <th className="px-6 py-4 text-left">Time</th>
                  <th className="px-6 py-4 text-left">Event ID</th>
                  <th className="px-6 py-4 text-left">Severity</th>
                  <th className="px-6 py-4 text-left">Source</th>
                  <th className="px-6 py-4 text-left">Hostname</th>
                  <th className="px-6 py-4 text-left">User</th>
                  <th className="px-6 py-4 text-left">Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id} className="border-t border-soc-border hover:bg-slate-900/80 cursor-pointer" onClick={() => setSelectedLog(log)}>
                    <td className="px-6 py-4 text-slate-200">{log.timestamp}</td>
                    <td className="px-6 py-4 text-slate-200">{log.event_id}</td>
                    <td className="px-6 py-4">
                      <Badge variant={severityStyles[log.severity]}>{log.severity}</Badge>
                    </td>
                    <td className="px-6 py-4 text-slate-200">{log.source}</td>
                    <td className="px-6 py-4 text-slate-200">{log.hostname}</td>
                    <td className="px-6 py-4 text-slate-200">{log.user}</td>
                    <td className="px-6 py-4 text-slate-200">
                      <span className="hover:text-white transition-colors">
                        {log.message.slice(0, 70)}
                        {log.message.length > 70 ? '…' : ''}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Pagination */}
      {!loading && logs.length > 0 && (
        <Pagination
          page={page}
          pageSize={pageSize}
          totalCount={totalCount}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      )}

      <LogDetailModal open={Boolean(selectedLog)} log={selectedLog ?? undefined} onClose={() => setSelectedLog(null)} />
    </div>
  );
}
