import { UserRole } from '../types';

export type Permission =
  | 'view_dashboard'
  | 'view_logs'
  | 'view_alerts'
  | 'view_endpoints'
  | 'view_ai_analysis'
  | 'view_audit_trail'
  | 'view_user_management'
  | 'acknowledge_alert'
  | 'resolve_alert'
  | 'mark_false_positive'
  | 'edit_alert'
  | 'manage_users'
  | 'create_user'
  | 'edit_user'
  | 'delete_user'
  | 'reset_password'
  | 'manage_endpoints'
  | 'isolate_endpoint'
  | 'rescan_endpoint'
  | 'update_endpoint_policy'
  | 'manage_settings';

export const sidebarItems = [
  {
    section: 'Security Monitoring',
    items: [
      { label: 'Dashboard', path: '/', permission: 'view_dashboard', icon: 'LayoutDashboard' },
      { label: 'Logs', path: '/logs', permission: 'view_logs', icon: 'FileSearch' },
      { label: 'Alerts', path: '/alerts', permission: 'view_alerts', icon: 'ShieldAlert' },
      { label: 'Endpoints', path: '/endpoints', permission: 'view_endpoints', icon: 'MonitorDot' },
      { label: 'AI Analysis', path: '/ai-analysis', permission: 'view_ai_analysis', icon: 'BrainCircuit' }
    ]
  },
  {
    section: 'Administration',
    items: [
      { label: 'Audit Trail', path: '/audit-trail', permission: 'view_audit_trail', icon: 'ClipboardList' },
      { label: 'User Management', path: '/user-management', permission: 'view_user_management', icon: 'Users' }
    ]
  }
];

const rolePermissions: Record<UserRole, Permission[]> = {
  admin: [
    'view_dashboard',
    'view_logs',
    'view_alerts',
    'view_endpoints',
    'view_ai_analysis',
    'view_audit_trail',
    'view_user_management',
    'acknowledge_alert',
    'resolve_alert',
    'mark_false_positive',
    'edit_alert',
    'manage_users',
    'create_user',
    'edit_user',
    'delete_user',
    'reset_password',
    'manage_endpoints',
    'isolate_endpoint',
    'rescan_endpoint',
    'update_endpoint_policy',
    'manage_settings',
  ],
  analyst: [
    'view_dashboard',
    'view_logs',
    'view_alerts',
    'view_endpoints',
    'view_ai_analysis',
    'view_audit_trail',
    'acknowledge_alert',
    'resolve_alert',
    'mark_false_positive',
    'edit_alert',
  ],
  viewer: [
    'view_dashboard',
    'view_alerts',
    'view_ai_analysis',
    'view_audit_trail',
  ],
};

export const normalizeRole = (role?: string | null): UserRole | null => {
  const normalized = String(role ?? '').toLowerCase();
  if (normalized === 'admin' || normalized === 'analyst' || normalized === 'viewer') {
    return normalized;
  }
  return null;
};

export const canPerformAction = (role: UserRole | string | null | undefined, action: Permission | string): boolean => {
  const normalizedRole = normalizeRole(role);
  if (!normalizedRole) return false;
  return rolePermissions[normalizedRole]?.includes(action as Permission) ?? false;
};

export const hasRole = (role: UserRole, ...roles: UserRole[]): boolean => {
  return roles.includes(role);
};
