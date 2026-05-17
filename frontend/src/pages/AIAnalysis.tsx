import { useEffect, useState } from 'react';
import { api } from '../lib/axios';
import { AnalysisItem } from '../types';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import Spinner from '../components/ui/Spinner';
import SessionIntelligencePanel from '../components/soc/SessionIntelligencePanel';

export default function AIAnalysis() {
  const [items, setItems] = useState<AnalysisItem[]>([]);
  const [summary, setSummary] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Manual Analysis States
  const [manualLog, setManualLog] = useState('');
  const [analyzingManual, setAnalyzingManual] = useState(false);
  const [manualResult, setManualResult] = useState<any>(null);

  useEffect(() => {
    fetchAnalysis();
  }, []);

  const fetchAnalysis = async () => {
    setLoading(true);
    try {
      const response = await api.get<{ summary: string; findings: AnalysisItem[] }>('/ai/threat-summary/');
      setSummary(response.data.summary);
      setItems(response.data.findings);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleManualAnalyze = async () => {
    if (!manualLog.trim()) return;
    setAnalyzingManual(true);
    setManualResult(null);
    try {
      const response = await api.post('/ai/analyze/', { log_text: manualLog });
      setManualResult(response.data);
    } catch (error) {
      console.error(error);
    } finally {
      setAnalyzingManual(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetchAnalysis();
    } finally {
      setRefreshing(false);
    }
  };

  const getScoreSeverity = (score: number): 'critical' | 'high' | 'medium' | 'low' => {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  };

  return (
    <div className="max-w-[1600px] mx-auto space-y-6 pb-12">
      {/* Header Section - Modern SOC Style */}
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between px-2">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-tight">AI Command Center</h2>
          <p className="mt-1 text-slate-400">Heuristic threat intelligence and real-time log forensics powered by Gemini.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden lg:flex flex-col items-end mr-2">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">System Status</span>
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs text-emerald-500 font-mono">Gemini-2.5-Flash Online</span>
            </div>
          </div>
          <Button
            variant="secondary"
            onClick={handleRefresh}
            disabled={refreshing}
            className="border-soc-border bg-slate-900"
          >
            {refreshing ? 'Syncing...' : 'Refresh Intel'}
          </Button>
        </div>
      </div>

      {/* Summary Banner */}
      <div className="panel-card bg-gradient-to-r from-slate-950 to-slate-900 border-l-4 border-l-soc-accent p-6">
        {loading ? (
          <div className="flex items-center gap-3">
            <Spinner size="sm" />
            <span className="text-slate-400 italic">Aggregating global threat data...</span>
          </div>
        ) : (
          <p className="text-lg text-slate-200 leading-relaxed">
            {summary || "Your log stream is currently healthy. No active threat clusters identified by the security model."}
          </p>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-12">
        {/* Left Control Column (4 cols) */}
        <div className="lg:col-span-4 space-y-6">
          <SessionIntelligencePanel />

          {/* Investigator Tool */}
          <div className="panel-card border-soc-accent/20 bg-soc-accent/5 overflow-hidden flex flex-col">
            <div className="p-5 border-b border-white/5 bg-white/5">
              <h3 className="text-md font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="text-soc-accent"><path d="m21 21-6-6"/><circle cx="10" cy="10" r="7"/></svg>
                Instant Investigator
              </h3>
            </div>
            
            <div className="p-5 space-y-4">
              <textarea
                className="w-full h-32 rounded-xl border border-soc-border bg-slate-950 p-4 text-sm text-slate-200 focus:ring-1 focus:ring-soc-accent outline-none font-mono transition-all resize-none scrollbar-thin scrollbar-thumb-slate-800"
                placeholder="Paste raw log data for AI inspection..."
                value={manualLog}
                onChange={(e) => setManualLog(e.target.value)}
              />
              
              <Button 
                className="w-full h-11 shadow-lg shadow-soc-accent/10" 
                onClick={handleManualAnalyze} 
                disabled={analyzingManual || !manualLog.trim()}
              >
                {analyzingManual ? 'Processing Log...' : 'Investigate with AI'}
              </Button>

              {/* Result Area - Fixed Height for Professionalism */}
              {manualResult && (
                <div className="mt-4 animate-in fade-in zoom-in-95 duration-300">
                  <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden shadow-2xl">
                    <div className="flex items-center justify-between px-4 py-2 bg-slate-900/80 border-b border-slate-800">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">Analysis Engine</span>
                      <Badge variant={manualResult.severity || 'low'} className="text-[9px] h-4">
                        {manualResult.threat_detected ? 'Malicious' : 'Clean'}
                      </Badge>
                    </div>
                    
                    <div className="p-4 max-h-[350px] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-xs font-bold text-soc-accent uppercase">{manualResult.threat_type || 'Generic Event'}</span>
                        <span className="text-[10px] text-slate-500 font-mono">Conf: {Math.round((manualResult.confidence || 0.8) * 100)}%</span>
                      </div>
                      
                      <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-sans bg-slate-900/50 p-3 rounded-lg border border-white/5">
                        {manualResult.description}
                      </div>

                      {manualResult.recommendations && (
                        <div className="mt-4 p-3 rounded-lg bg-amber-950/20 border border-amber-900/30">
                          <p className="text-[10px] text-amber-500 font-black uppercase mb-1">Recommended Response</p>
                          <p className="text-[11px] text-slate-400 leading-normal">{manualResult.recommendations}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Intelligence Column (8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          <div className="flex items-center justify-between px-2">
            <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Active Threat Timeline</h3>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-red-500" />
                <span className="text-[10px] text-slate-400 uppercase">Critical</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-orange-500" />
                <span className="text-[10px] text-slate-400 uppercase">High</span>
              </div>
            </div>
          </div>

          {loading ? (
            <div className="panel-card h-[400px] flex flex-col items-center justify-center border-dashed">
              <Spinner size="md" />
              <p className="mt-4 text-sm text-slate-500 font-mono">Querying intelligence database...</p>
            </div>
          ) : items.length === 0 ? (
            <div className="panel-card h-[400px] border-dashed border-2 flex flex-col items-center justify-center text-center p-10 bg-slate-900/20">
              <div className="w-16 h-16 rounded-full bg-slate-800/50 flex items-center justify-center mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" className="text-slate-600"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>
              </div>
              <h4 className="text-white text-lg font-medium">No Threats Detected</h4>
              <p className="text-slate-500 text-sm max-w-xs mt-2 italic">Gemini has not identified any recurring patterns in your recent fleet logs. All systems are operating within normal parameters.</p>
            </div>
          ) : (
            <div className="space-y-4 max-h-[1000px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-800">
              {items.map((item) => (
                <div key={item.id} className="panel-card p-0 group hover:border-soc-accent/40 transition-all overflow-hidden">
                  <div className="p-6">
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold text-soc-accent uppercase tracking-widest">{item.category}</span>
                          <span className="text-[10px] text-slate-600">•</span>
                          <span className="text-[10px] text-slate-500 font-mono">DET-ID: {item.id}</span>
                        </div>
                        <h3 className="text-xl font-bold text-white group-hover:text-soc-accent transition-colors">{item.title}</h3>
                      </div>
                      <Badge variant={getScoreSeverity(item.score)} className="scale-110">
                        {item.score}% Risk
                      </Badge>
                    </div>

                    <div className="mt-6 flex gap-4 items-center">
                      <div className="flex-1 h-1 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full transition-all duration-1000 ${
                            getScoreSeverity(item.score) === 'critical' ? 'bg-red-500' : 
                            getScoreSeverity(item.score) === 'high' ? 'bg-orange-500' : 'bg-blue-500'
                          }`}
                          style={{ width: `${item.score}%` }}
                        />
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">{item.score}/100</span>
                    </div>

                    <p className="mt-6 text-sm text-slate-300 leading-relaxed border-l-2 border-slate-800 pl-4 py-1 italic">
                      {item.summary}
                    </p>

                    <div className="mt-6 grid md:grid-cols-2 gap-4">
                      <div className="rounded-2xl bg-slate-950/50 p-4 border border-white/5">
                        <p className="text-[9px] font-black text-slate-500 uppercase tracking-tighter mb-2">SOC Recommendation</p>
                        <p className="text-xs text-slate-200 leading-normal">{item.recommendation}</p>
                      </div>
                      
                      {item.related_log_ids.length > 0 && (
                        <div className="rounded-2xl bg-slate-950/50 p-4 border border-white/5">
                          <p className="text-[9px] font-black text-slate-500 uppercase tracking-tighter mb-2">Correlated Events</p>
                          <div className="flex flex-wrap gap-2">
                            {item.related_log_ids.map((logId) => (
                              <span key={logId} className="px-2 py-1 rounded-md bg-slate-900 text-[10px] text-slate-500 font-mono border border-slate-800">
                                LOG#{logId}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
