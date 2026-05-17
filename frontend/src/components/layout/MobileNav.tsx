import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { canPerformAction, sidebarItems } from '../../lib/rbac';
import {
  BrainCircuit,
  ClipboardList,
  FileSearch,
  LayoutDashboard,
  MonitorDot,
  ShieldAlert,
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

export interface MobileNavProps {
  open: boolean;
  onClose: () => void;
}

const MobileNav: React.FC<MobileNavProps> = ({ open, onClose }) => {
  const { user } = useAuth();

  if (!open) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-slate-950/50 lg:hidden"
        onClick={onClose}
      />
      <div className="fixed inset-y-0 left-0 z-50 w-64 overflow-y-auto border-r border-soc-border bg-slate-950/95 p-4 lg:hidden">
        <nav className="space-y-6">
          {sidebarItems.map((section) => (
            <div key={section.section}>
              <p className="px-4 text-xs uppercase tracking-[0.3em] text-slate-500 font-semibold">
                {section.section}
              </p>
              <ul className="mt-3 space-y-1">
                {section.items
                  .filter((item) => canPerformAction(user?.role, item.permission))
                  .map((item) => {
                    const Icon = icons[item.icon as keyof typeof icons];
                    return (
                      <li key={item.path}>
                        <Link
                          to={item.path}
                          onClick={onClose}
                          className="flex items-center gap-3 rounded-lg px-4 py-2.5 text-sm text-slate-300 transition-colors hover:bg-slate-800 hover:text-white"
                        >
                          <Icon className="h-4 w-4" aria-hidden />
                          {item.label}
                        </Link>
                      </li>
                    );
                  })}
              </ul>
            </div>
          ))}
        </nav>
      </div>
    </>
  );
};

export default MobileNav;
