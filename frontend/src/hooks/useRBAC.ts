import { useAuth } from '../context/AuthContext';
import { canPerformAction } from '../lib/rbac';

export interface PermissionCheck {
  can: (action: string) => boolean;
  cannot: (action: string) => boolean;
}

export const useRBAC = (): PermissionCheck => {
  const { user } = useAuth();

  const can = (action: string): boolean => {
    if (!user) return false;
    return canPerformAction(user.role, action);
  };

  const cannot = (action: string): boolean => {
    return !can(action);
  };

  return { can, cannot };
};
