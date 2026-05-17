import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import MobileNav from './MobileNav';
import { useAuth } from '../../context/AuthContext';

export default function Layout() {
  const { loading } = useAuth();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-soc-surface px-4">
        <div className="rounded-3xl border border-soc-border bg-slate-950/95 px-8 py-10 text-slate-200 shadow-panel">
          <p className="text-lg font-semibold">Loading security console…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-soc-surface text-slate-100 flex flex-col">
      <Header
        onMenuToggle={() => setMobileNavOpen(!mobileNavOpen)}
        showMenuIcon
      />
      <MobileNav open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />

      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <div className="px-4 py-6 lg:px-8 lg:py-8">
            <div className="max-w-[1600px] mx-auto">
              <Outlet />
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
