import { NavLink } from 'react-router-dom';
import { canPerformAction, sidebarItems } from '../../lib/rbac';
import { useAuth } from '../../context/AuthContext';
import {
  BrainCircuit,
  ClipboardList,
  FileSearch,
  LayoutDashboard,
  MonitorDot,
  ShieldAlert,
  ShieldCheck,
  Users
} from 'lucide-react';

const icons = {
  LayoutDashboard,
  FileSearch,
  ShieldAlert,
  MonitorDot,
  BrainCircuit,
  ClipboardList,
  Users
};

export default function Sidebar() {
  const { user } = useAuth();

  return (
    <aside className="hidden xl:flex xl:w-72 xl:flex-col border-r border-soc-border bg-slate-950/95 px-4 py-6">
      <div className="mb-10 flex items-center gap-3 text-slate-100">
        <div className="h-11 w-11 rounded-2xl bg-soc-accent/20 flex items-center justify-center text-soc-accent">
          <ShieldCheck className="h-6 w-6" aria-hidden />
        </div>
        <div>
          <p className="text-sm uppercase tracking-[0.3em] text-slate-500">SOC Console</p>
          <h1 className="text-xl font-semibold">Security Platform</h1>
        </div>
      </div>

      {sidebarItems.map((section) => (
        <div key={section.section} className="mb-8">
          <p className="mb-3 text-xs uppercase tracking-[0.25em] text-slate-500">{section.section}</p>
          <div className="space-y-2">
            {section.items
              .filter((item) => canPerformAction(user?.role, item.permission))
              .map((item) => {
                const Icon = icons[item.icon as keyof typeof icons];
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm font-medium transition ${
                        isActive ? 'bg-soc-accent/10 text-white shadow-lg shadow-soc-accent/10' : 'text-slate-300 hover:bg-slate-800/80'
                      }`
                    }
                  >
                    <Icon className="h-4 w-4" aria-hidden />
                    {item.label}
                  </NavLink>
                );
              })}
          </div>
        </div>
      ))}
    </aside>
  );
}
