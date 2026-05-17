import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Spinner from '../ui/Spinner';
import { LogEvent } from '../../types';

interface LogDetailModalProps {
  open: boolean;
  log?: LogEvent;
  onClose: () => void;
}

export default function LogDetailModal({ open, log, onClose }: LogDetailModalProps) {
  if (!open || !log) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/70 px-4 py-8 sm:items-center">
      <div className="w-full max-w-4xl rounded-3xl border border-soc-border bg-slate-950/95 p-6 shadow-panel">
        <div className="mb-6 flex items-start justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Log detail</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">Event {log.event_id} • {log.hostname}</h3>
          </div>
          <Button variant="ghost" onClick={onClose}>Close</Button>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          {/* Metadata Column */}
          <div className="space-y-4">
            <div className="space-y-3 rounded-3xl border border-soc-border bg-slate-900/95 p-4">
              <div className="flex items-center justify-between gap-4">
                <p className="text-sm text-slate-400">Severity</p>
                <Badge variant={log.severity}>{log.severity}</Badge>
              </div>
              <div>
                <p className="text-sm text-slate-400">Source</p>
                <p className="mt-1 text-sm text-slate-100 font-medium">{log.source}</p>
              </div>
              <div>
                <p className="text-sm text-slate-400">User</p>
                <p className="mt-1 text-sm text-slate-100 font-medium">{log.user}</p>
              </div>
              <div>
                <p className="text-sm text-slate-400">Timestamp</p>
                <p className="mt-1 text-sm text-slate-100">{log.timestamp}</p>
              </div>
            </div>

            {/* AI Status Card */}
            <div className="rounded-3xl border border-emerald-900/30 bg-emerald-950/20 p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">AI Guard Status</span>
              </div>
              <p className="text-xs text-slate-300">
                {log.analyzed ? 'Deep analysis complete' : 'Analysis in progress...'}
              </p>
            </div>
          </div>

          {/* Main Content Area */}
          <div className="md:col-span-2 space-y-4">
            {/* AI Analyst Insights Section */}
            <div className="rounded-3xl border border-soc-accent/30 bg-soc-accent/5 p-5">
              <div className="flex items-center gap-2 mb-4">
                <span className="text-sm font-semibold text-soc-accent">Gemini AI Analyst Insights</span>
                {log.analyzed && (
                  <Badge variant={log.ai_threat_detected ? 'high' : 'success'}>
                    {log.ai_threat_detected ? 'Threat Detected' : 'No Threat Found'}
                  </Badge>
                )}
              </div>

              {!log.analyzed ? (
                <div className="flex items-center gap-3 py-4">
                  <Spinner size="sm" />
                  <p className="text-sm text-slate-400 italic">Waiting for Gemini security analysis...</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="rounded-2xl bg-slate-900/50 p-3">
                      <p className="text-xs text-slate-500 uppercase">Detection Type</p>
                      <p className="mt-1 text-sm text-slate-200 font-mono capitalize">{log.ai_threat_type || 'N/A'}</p>
                    </div>
                    <div className="rounded-2xl bg-slate-900/50 p-3">
                      <p className="text-xs text-slate-500 uppercase">AI Confidence</p>
                      <p className="mt-1 text-sm text-slate-200 font-mono">{(log.ai_analysis?.confidence ?? 0) * 100}%</p>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-xs text-slate-500 uppercase mb-2">AI Summary</p>
                    <p className="text-sm text-slate-200 leading-relaxed bg-slate-950/50 rounded-2xl p-4 border border-slate-800">
                      {log.ai_analysis?.description || 'No analysis available for this event yet.'}
                    </p>
                  </div>

                  {log.ai_analysis?.recommendation && (
                    <div className="rounded-2xl bg-amber-950/10 border border-amber-900/20 p-4">
                      <p className="text-xs text-amber-500 uppercase font-bold mb-1">Recommended Action</p>
                      <p className="text-sm text-slate-300">{log.ai_analysis.recommendation}</p>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="rounded-3xl border border-soc-border bg-slate-900/95 p-4">
              <p className="text-sm text-slate-400">Log Message</p>
              <p className="mt-2 text-sm font-mono leading-6 text-slate-200 bg-slate-950 p-3 rounded-2xl">{log.message}</p>
            </div>
          </div>
        </div>

        <div className="mt-6 rounded-3xl border border-soc-border bg-slate-900/95 p-4">
          <p className="text-sm text-slate-400">Raw Sysmon Payload</p>
          <pre className="mt-3 max-h-48 overflow-auto rounded-2xl bg-slate-950 p-4 text-xs leading-5 text-slate-200 scrollbar-thin scrollbar-thumb-slate-800">
            {log.raw_data || 'No raw event payload available.'}
          </pre>
        </div>
      </div>
    </div>
  );
}
