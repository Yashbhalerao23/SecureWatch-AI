import { useEffect, useState } from 'react';
import { api } from '../lib/axios';
import { AuditEventItem } from '../types';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Pagination from '../components/ui/Pagination';
import Spinner from '../components/ui/Spinner';

export default function AuditTrail() {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchEvents();
  }, [userFilter, actionFilter, page, pageSize]);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const response = await api.get<{ results: AuditEventItem[]; count: number }>('/audit-events/', {
        params: {
          user: userFilter || undefined,
          action: actionFilter || undefined,
          page,
          page_size: pageSize,
        },
      });
      setEvents(response.data.results);
      setTotalCount(response.data.count);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetchEvents();
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="panel-card p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">Audit Trail</h2>
            <p className="mt-2 text-sm text-slate-400">
              Track security events including login activity, role changes, and alert handling.
            </p>
          </div>
          <Button
            variant="secondary"
            onClick={handleRefresh}
            disabled={refreshing}
            size="sm"
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </Button>
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          <Input
            placeholder="Filter by user"
            value={userFilter}
            onChange={(event) => {
              setUserFilter(event.target.value);
              setPage(1);
            }}
          />
          <Input
            placeholder="Filter by action"
            value={actionFilter}
            onChange={(event) => {
              setActionFilter(event.target.value);
              setPage(1);
            }}
          />
          <Button variant="secondary" className="lg:col-span-1">
            Export as CSV
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="panel-card overflow-hidden">
        <div className="overflow-x-auto">
          {loading ? (
            <div className="flex justify-center py-10">
              <Spinner size="md" text="Loading audit events..." />
            </div>
          ) : events.length === 0 ? (
              <div className="px-6 py-10 text-center text-slate-500">No audit entries found.</div>
          ) : (
            <table className="min-w-full border-separate border-spacing-0 text-sm">
              <thead className="bg-slate-950/95 text-slate-400">
                <tr>
                  <th className="px-6 py-4 text-left">Timestamp</th>
                  <th className="px-6 py-4 text-left">User</th>
                  <th className="px-6 py-4 text-left">Action</th>
                  <th className="px-6 py-4 text-left">Target</th>
                  <th className="px-6 py-4 text-left">IP</th>
                  <th className="px-6 py-4 text-left">Device fingerprint</th>
                  <th className="px-6 py-4 text-left">Browser</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id} className="border-t border-soc-border hover:bg-slate-900/80">
                    <td className="px-6 py-4 text-slate-200">{event.created_at}</td>
                    <td className="px-6 py-4 text-slate-200">{event.user}</td>
                    <td className="px-6 py-4 text-slate-200">{event.action}</td>
                    <td className="px-6 py-4 text-slate-200">{event.target}</td>
                    <td className="px-6 py-4 text-slate-200">{event.ip_address}</td>
                    <td className="px-6 py-4 font-mono text-xs text-slate-200">{event.device_fingerprint ?? event.device}</td>
                    <td className="px-6 py-4 text-slate-200">{event.browser ?? 'Unknown'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Pagination */}
      {!loading && events.length > 0 && (
        <Pagination
          page={page}
          pageSize={pageSize}
          totalCount={totalCount}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      )}
    </div>
  );
}
