import { motion } from 'framer-motion';
import Badge from '../ui/Badge';
import { useSessionIntelligence } from '../../context/SessionIntelligenceContext';

function statusToBadgeVariant(status?: string) {
  if (!status) return 'info';
  if (status === 'suspicious') return 'critical';
  if (status === 'new') return 'high';
  return 'success';
}

export default function SessionIntelligencePanel() {
  const { intelligence, deviceMetadata, loading } = useSessionIntelligence();

  return (
    <div className="panel-card p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Login intelligence</p>
          <h3 className="mt-2 text-lg font-semibold text-white">Session security posture</h3>
        </div>

        <motion.div
          initial={{ scale: 0.98, opacity: 0.7 }}
          animate={{ scale: [1, 1.02, 1], opacity: 1 }}
          transition={{ duration: 2, repeat: loading ? 0 : Infinity, repeatDelay: 3 }}
          className="flex items-center gap-2"
        >
          {/* icon-free to avoid missing lucide-react types in some setups */}
          <Badge variant={statusToBadgeVariant(intelligence?.deviceStatus)}>
            {loading ? 'Analyzing…' : intelligence?.deviceStatus ?? 'unknown'}
          </Badge>
        </motion.div>
      </div>

      <div className="mt-5 space-y-3 text-sm text-slate-300">
        <div className="flex items-center justify-between rounded-3xl border border-soc-border bg-slate-950/95 px-4 py-3">
          <span>Device fingerprint</span>
          <span className="font-mono text-xs text-slate-200">{deviceMetadata?.deviceId ?? '—'}</span>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-3xl border border-soc-border bg-slate-950/95 p-4">
            <p className="text-xs uppercase tracking-[0.22em] text-slate-500">OS</p>
            <p className="mt-2 text-sm text-slate-100">{deviceMetadata?.os ?? '—'}</p>
          </div>
          <div className="rounded-3xl border border-soc-border bg-slate-950/95 p-4">
            <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Timezone</p>
            <p className="mt-2 text-sm text-slate-100">{deviceMetadata?.timezone ?? '—'}</p>
          </div>
        </div>

        {intelligence ? (
          <div className="rounded-3xl border border-soc-border bg-slate-950/95 p-4">
            <p className="text-sm text-slate-400">Security findings</p>
            <ul className="mt-2 space-y-1 text-slate-200">
              <li>Browser changed: {intelligence.browserChanged ? 'Yes' : 'No'}</li>
              <li>OS changed: {intelligence.osChanged ? 'Yes' : 'No'}</li>
              <li>Unusual login location: {intelligence.unusualLocation ? 'Yes' : 'No'}</li>
            </ul>
          </div>
        ) : (
          <div className="rounded-3xl border border-soc-border bg-slate-950/95 p-4 text-slate-400">
            No session intelligence available.
          </div>
        )}
      </div>
    </div>
  );
}

