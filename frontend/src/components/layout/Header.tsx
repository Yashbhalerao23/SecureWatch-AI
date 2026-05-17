import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import Button from '../ui/Button';
import { LogOut, Menu, RadioTower } from 'lucide-react';

export interface HeaderProps {
  onMenuToggle?: () => void;
  showMenuIcon?: boolean;
}

const Header: React.FC<HeaderProps> = ({ onMenuToggle, showMenuIcon = true }) => {
  const { user, logout } = useAuth();

  return (
    <div className="flex items-center justify-between gap-4 border-b border-soc-border bg-slate-950/95 px-6 py-4">
      <div className="flex items-center gap-4">
        {showMenuIcon && (
          <button
            onClick={onMenuToggle}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 lg:hidden"
            aria-label="Toggle menu"
          >
            <Menu className="h-6 w-6" aria-hidden />
          </button>
        )}
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">SOC Console</p>
          <p className="flex items-center gap-2 text-sm font-semibold text-slate-300">
            <RadioTower className="h-4 w-4 text-soc-accent" aria-hidden />
            Security Operations Center
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {user && (
          <>
            <div className="hidden sm:block text-right">
              <p className="text-sm font-medium text-slate-200">{user.fullName}</p>
              <p className="text-xs uppercase tracking-[0.1em] text-slate-500">{user.role}</p>
            </div>
            <Button variant="ghost" size="sm" onClick={logout}>
              <span className="inline-flex items-center gap-2">
                <LogOut className="h-4 w-4" aria-hidden />
                Logout
              </span>
            </Button>
          </>
        )}
      </div>
    </div>
  );
};

export default Header;
