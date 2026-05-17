import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/axios';
import MetricCard from '../components/metrics/MetricCard';
import Badge from '../components/ui/Badge';
import { AlertItem } from '../types';
import SessionIntelligencePanel from '../components/soc/SessionIntelligencePanel';
import { useSocRealtime } from '../hooks/useSocRealtime';
import Spinner from '../components/ui/Spinner';

export interface DashboardPayload {
  total_logs_today: number;
  active_alerts: number;
  critical_threats: number;
  online_endpoints: number;
  failed_login_attempts: number;
  suspicious_powershell_events: number;
  recent_incidents: AlertItem[];
  recent_alerts: AlertItem[];
  severity_distribution: Array<{ severity: string; count: number }>;
  ingestion_activity: Array<{ timestamp: string; events: number }>;
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = useCallback(async () => {
    try {
      const response = await api.get<DashboardPayload>('/dashboard/metrics/');
      setData(response.data);
    } catch (error) {
      console.error("Dashboard Metrics Load Error:", error);
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchMetrics();
  }, [fetchMetrics]);

  const { connected } = useSocRealtime(
    useCallback((message) => {
      if (['alert.created', 'log.ingested'].includes(message.type)) {
        void fetchMetrics();
      }
    }, [fetchMetrics]),
    ['dashboard']
  );

  const handlePrintReport = () => {
    window.print();
  };

  if (loading) {
    return (
      <div className="flex h-[80vh] items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Spinner size="md" />
          <p className="text-sm font-mono text-slate-500 animate-pulse uppercase tracking-[0.2em]">Aggregating SOC Telemetry...</p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex h-[80vh] items-center justify-center px-4">
        <div className="panel-card p-12 text-center max-w-md border-red-900/20 bg-red-950/5">
          <div className="mx-auto w-16 h-16 rounded-3xl bg-red-950 flex items-center justify-center mb-6 text-red-500 border border-red-500/20">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
          </div>
          <h4 className="text-xl font-bold text-white mb-2">Telemetry Disconnected</h4>
          <button onClick={() => window.location.reload()} className="w-full py-3 rounded-2xl bg-white text-black font-bold text-xs uppercase tracking-widest hover:bg-slate-200 transition-all">
            Reconnect to Engine
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-[1600px] mx-auto space-y-6 pb-12 print:p-0">
      {/* Dynamic Header */}
      <div className="flex flex-col md:flex-row md:items-end md:justify-between px-2 gap-4 print:mb-8">
        <div>
          <h2 className="text-3xl font-black text-white tracking-tight uppercase print:text-black print:text-2xl">Security Dashboard</h2>
          <div className="flex items-center gap-3 mt-1 print:hidden">
            <p className="text-slate-500 text-sm font-medium">Real-time threat monitoring and fleet telemetry</p>
            <span className="text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`} />
              <span className={`text-[10px] font-bold uppercase tracking-widest ${connected ? 'text-emerald-500' : 'text-slate-500'}`}>
                {connected ? 'Streaming' : 'Polling'}
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 bg-slate-900/50 p-1 rounded-xl border border-white/5 print:hidden">
          <div className="px-3 py-1.5 rounded-lg bg-slate-950 text-[10px] font-bold text-slate-400 uppercase tracking-tighter border border-white/5">
            Fleet: Online
          </div>
          <button 
            onClick={handlePrintReport}
            className="px-3 py-1.5 rounded-lg text-[10px] font-bold text-white bg-soc-accent uppercase tracking-tighter hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-soc-accent/20"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect width="12" height="8" x="6" y="14"/></svg>
            Generate PDF Report
          </button>
        </div>
      </div>

      {/* High Impact Metrics */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 print:grid-cols-3 print:gap-2">
        <MetricCard label="Logs (24h)" value={data.total_logs_today} description="Total ingested security events" severity="info" />
        <MetricCard label="Active Alerts" value={data.active_alerts} description="Events requiring triage" severity={data.active_alerts > 0 ? 'high' : 'success'} />
        <MetricCard label="Critical" value={data.critical_threats} description="Priority 1 response" severity={data.critical_threats > 0 ? 'critical' : 'success'} />
        <MetricCard label="Endpoints" value={data.online_endpoints} description="Systems reporting" severity="info" />
        <MetricCard label="Failed Logins" value={data.failed_login_attempts} description="Auth failures detected" severity={data.failed_login_attempts > 20 ? 'high' : 'medium'} />
        <MetricCard label="Suspicious" value={data.suspicious_powershell_events} description="AI-flagged PowerShell" severity={data.suspicious_powershell_events > 0 ? 'high' : 'low'} />
      </section>

      <div className="grid gap-6 lg:grid-cols-12 print:block print:space-y-6">
        {/* Left Column (Main Feed) */}
        <div className="lg:col-span-8 space-y-6 print:w-full">
          
          {/* Threat Queue */}
          <div className="panel-card p-0 overflow-hidden shadow-2xl print:border-black print:shadow-none">
            <div className="px-6 py-4 border-b border-white/5 bg-white/5 flex items-center justify-between print:bg-gray-100 print:border-black">
              <div className="flex items-center gap-2">
                 <div className="p-1.5 rounded-lg bg-red-500/10 text-red-500 print:hidden">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
                 </div>
                 <h3 className="text-xs font-black text-white uppercase tracking-widest print:text-black">Active Incident Queue</h3>
              </div>
              <Badge variant="high" className="text-[9px] print:border-black print:text-black">High Priority Only</Badge>
            </div>
            
            <div className="p-6">
              {data.recent_incidents.length === 0 ? (
                <div className="py-10 text-center border-2 border-dashed border-slate-800 rounded-[2rem] print:border-black">
                  <p className="text-slate-500 font-medium italic print:text-black">No critical incidents detected.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {data.recent_incidents.map((incident) => (
                    <div key={incident.id} className="flex items-center justify-between p-4 rounded-2xl bg-slate-950/50 border border-white/5 print:bg-white print:border-black print:text-black">
                      <div className="flex items-center gap-4">
                        <div className={`w-1 h-8 rounded-full ${incident.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'} print:bg-black`} />
                        <div>
                          <p className="text-sm font-bold text-slate-100 print:text-black">{incident.title}</p>
                          <p className="text-[10px] text-slate-500 font-mono mt-0.5 print:text-black">{incident.hostname} • {incident.source}</p>
                        </div>
                      </div>
                      <div className="text-right">
                         <Badge variant={incident.severity} className="text-[9px] uppercase print:border-black print:text-black">{incident.severity}</Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Activity Section */}
          <div className="grid gap-6 md:grid-cols-2 print:grid-cols-2 print:gap-4">
            <div className="panel-card p-6 bg-slate-950/50 print:bg-white print:border-black">
              <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-6 print:text-black">Ingestion Velocity (6h)</h4>
              <div className="space-y-4">
                {data.ingestion_activity.map((row) => (
                  <div key={row.timestamp} className="flex items-center gap-4">
                    <span className="text-[10px] font-mono text-slate-600 w-12 print:text-black">{row.timestamp}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-slate-900 overflow-hidden print:border print:border-black">
                      <div className="h-full bg-soc-accent print:bg-black" style={{ width: `${Math.min(100, (row.events/100)*100)}%` }} />
                    </div>
                    <span className="text-[10px] font-bold text-slate-500 print:text-black">{row.events} msg</span>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="panel-card p-6 bg-slate-950/50 print:bg-white print:border-black">
              <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-6 print:text-black">Risk Profile</h4>
              <div className="space-y-5">
                {data.severity_distribution.map((item) => (
                  <div key={item.severity} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter print:text-black">{item.severity}</span>
                      <span className="text-xs font-black text-white print:text-black">{item.count}</span>
                    </div>
                    <div className="h-1 w-full bg-slate-900 rounded-full overflow-hidden print:border print:border-black">
                       <div className={`h-full ${item.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'} print:bg-black`} style={{ width: `${(item.count/data.active_alerts || 1)*100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (Side Panels) */}
        <div className="lg:col-span-4 space-y-6 print:w-full">
          <div className="print:hidden">
             <SessionIntelligencePanel />
          </div>
          
          <div className="panel-card border-soc-accent/20 bg-soc-accent/5 p-0 overflow-hidden print:bg-white print:border-black">
            <div className="px-5 py-4 border-b border-white/5 bg-white/5 flex items-center justify-between print:bg-gray-100 print:border-black">
              <h3 className="text-[10px] font-black text-white uppercase tracking-[0.2em] print:text-black">Global Threat Stream</h3>
            </div>
            <div className="p-5 space-y-4 max-h-[500px] overflow-y-auto scrollbar-thin print:max-h-none">
              {data.recent_alerts.map((alert) => (
                <div key={alert.id} className="relative pl-6 py-1 print:pl-0 print:border-b print:border-gray-200">
                  <div className={`absolute left-0 top-2 bottom-2 w-0.5 rounded-full ${alert.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'} print:hidden`} />
                  <p className="text-[11px] font-bold text-slate-200 truncate print:text-black">{alert.title}</p>
                  <p className="text-[9px] text-slate-600 font-mono print:text-black">{alert.hostname || 'Global'} • Just now</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
