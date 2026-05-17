import { useEffect, useState } from 'react';
import { api } from '../lib/axios';
import { EndpointItem } from '../types';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';
import Select from '../components/ui/Select';
import Button from '../components/ui/Button';
import EndpointDetailModal from '../components/modals/EndpointDetailModal';

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'offline' | 'warning'>('all');
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointItem | null>(null);

  useEffect(() => {
    async function fetchEndpoints() {
      setLoading(true);
      try {
        const response = await api.get<EndpointItem[]>('/endpoints/');
        setEndpoints(response.data);
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    }

    fetchEndpoints();
  }, []);

  const filteredEndpoints = endpoints.filter((endpoint) => {
    const matchesSearch =
      endpoint.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      endpoint.ip_address.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || endpoint.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleDetailClick = (endpoint: EndpointItem) => {
    setSelectedEndpoint(endpoint);
    setDetailModalOpen(true);
  };

  const getRiskColor = (riskScore: number): 'critical' | 'high' | 'medium' | 'low' | 'success' => {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    if (riskScore >= 20) return 'low';
    return 'success';
  };

  return (
    <div className="space-y-6">
      <div className="panel-card p-6">
        <h2 className="text-xl font-semibold text-white">Endpoints</h2>
        <p className="mt-2 text-sm text-slate-400">Monitored hosts and their risk posture based on Windows log telemetry.</p>
      </div>

      {/* Filters */}
      <div className="panel-card p-6 space-y-4">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <Input
            label="Search"
            placeholder="Hostname or IP address"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <Select
            label="Status"
            options={[
              { value: 'all', label: 'All Status' },
              { value: 'online', label: 'Online' },
              { value: 'offline', label: 'Offline' },
              { value: 'warning', label: 'Warning' },
            ]}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
          />
          <div className="flex items-end">
            <Button variant="secondary" className="w-full">
              Advanced Filters
            </Button>
          </div>
        </div>
        <p className="text-sm text-slate-400">
          Showing <span className="font-semibold">{filteredEndpoints.length}</span> endpoints
        </p>
      </div>

      {/* Endpoints Grid */}
      <div className="grid gap-6 xl:grid-cols-3">
        {loading ? (
          <div className="panel-card col-span-3 p-6 text-center text-slate-500">Loading endpoint inventory…</div>
        ) : filteredEndpoints.length === 0 ? (
          <div className="panel-card col-span-3 p-6 text-center text-slate-500">No endpoints match your filters.</div>
        ) : (
          filteredEndpoints.map((endpoint) => (
            <div
              key={endpoint.id}
              className="panel-card p-6 cursor-pointer transition-all hover:border-soc-accent hover:shadow-lg hover:shadow-soc-accent/10"
              onClick={() => handleDetailClick(endpoint)}
            >
              <div className="flex items-center justify-between gap-4 mb-4">
                <div>
                  <p className="text-sm text-slate-500">Hostname</p>
                  <p className="mt-1 text-lg font-semibold text-white">{endpoint.hostname}</p>
                </div>
                <Badge
                  variant={
                    endpoint.status === 'online'
                      ? 'success'
                      : endpoint.status === 'warning'
                        ? 'high'
                        : 'medium'
                  }
                >
                  {endpoint.status}
                </Badge>
              </div>

              <div className="space-y-3">
                <div className="rounded-2xl border border-soc-border bg-slate-900/50 p-3">
                  <p className="text-xs text-slate-400">IP Address</p>
                  <p className="mt-1 text-sm text-slate-200">{endpoint.ip_address}</p>
                </div>
                <div className="rounded-2xl border border-soc-border bg-slate-900/50 p-3">
                  <p className="text-xs text-slate-400">Operating System</p>
                  <p className="mt-1 text-sm text-slate-200">{endpoint.os}</p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-2xl border border-soc-border bg-slate-900/50 p-3">
                    <p className="text-xs text-slate-400">Risk Score</p>
                    <div className="mt-2 flex items-center gap-2">
                      <div className="h-2 flex-1 rounded-full bg-slate-700 overflow-hidden">
                        <div
                          className={`h-full transition-all ${
                            getRiskColor(endpoint.risk_score) === 'critical'
                              ? 'bg-red-600'
                              : getRiskColor(endpoint.risk_score) === 'high'
                                ? 'bg-orange-500'
                                : getRiskColor(endpoint.risk_score) === 'medium'
                                  ? 'bg-yellow-500'
                                  : 'bg-emerald-500'
                          }`}
                          style={{ width: `${endpoint.risk_score}%` }}
                        />
                      </div>
                      <span className="text-sm font-semibold text-slate-200">{endpoint.risk_score}%</span>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-soc-border bg-slate-900/50 p-3">
                    <p className="text-xs text-slate-400">Alerts</p>
                    <p className="mt-2 text-lg font-semibold text-slate-200">{endpoint.total_alerts}</p>
                  </div>
                </div>
                <div className="rounded-2xl border border-soc-border bg-slate-900/50 p-3">
                  <p className="text-xs text-slate-400">Last Seen</p>
                  <p className="mt-1 text-sm text-slate-200">{endpoint.last_seen}</p>
                </div>
              </div>

              <Button variant="ghost" className="w-full mt-4" size="sm">
                View Details
              </Button>
            </div>
          ))
        )}
      </div>

      {selectedEndpoint && (
        <EndpointDetailModal
          open={detailModalOpen}
          onOpenChange={setDetailModalOpen}
          endpointId={selectedEndpoint.id}
          hostname={selectedEndpoint.hostname}
        />
      )}
    </div>
  );
}
