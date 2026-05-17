import { Link } from 'react-router-dom';
import Button from '../components/ui/Button';

export default function NotFound() {
  return (
    <div className="grid min-h-[70vh] place-items-center px-4">
      <div className="rounded-3xl border border-soc-border bg-slate-950/95 p-10 text-center shadow-panel">
        <p className="text-sm uppercase tracking-[0.3em] text-slate-500">Page not found</p>
        <h1 className="mt-4 text-5xl font-semibold text-white">404</h1>
        <p className="mt-4 text-sm leading-7 text-slate-400">The route you requested is not available in this SOC dashboard.</p>
        <Link to="/">
          <Button variant="secondary" className="mt-6">Return to dashboard</Button>
        </Link>
      </div>
    </div>
  );
}
