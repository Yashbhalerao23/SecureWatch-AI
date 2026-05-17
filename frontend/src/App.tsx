import { Route, Routes, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SessionIntelligenceProvider } from './context/SessionIntelligenceContext';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Logs from './pages/Logs';
import Alerts from './pages/Alerts';
import Endpoints from './pages/Endpoints';
import AIAnalysis from './pages/AIAnalysis';
import AuditTrail from './pages/AuditTrail';
import UserManagement from './pages/UserManagement';
import Login from './pages/Login';
import NotFound from './pages/NotFound';
import { canPerformAction, Permission } from './lib/rbac';

function RequirePermission({
  children,
  permission
}: {
  children: React.ReactNode;
  permission: Permission;
}) {
  const { user } = useAuth();

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (!canPerformAction(user.role, permission)) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return null;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="logs" element={<RequirePermission permission="view_logs"><Logs /></RequirePermission>} />
        <Route path="alerts" element={<RequirePermission permission="view_alerts"><Alerts /></RequirePermission>} />
        <Route path="endpoints" element={<RequirePermission permission="view_endpoints"><Endpoints /></RequirePermission>} />
        <Route path="ai-analysis" element={<RequirePermission permission="view_ai_analysis"><AIAnalysis /></RequirePermission>} />
        <Route
          path="audit-trail"
          element={
            <RequirePermission permission="view_audit_trail">
              <AuditTrail />
            </RequirePermission>
          }
        />
        <Route
          path="user-management"
          element={
            <RequirePermission permission="view_user_management">
              <UserManagement />
            </RequirePermission>
          }
        />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <SessionIntelligenceProvider>
        <AppRoutes />
      </SessionIntelligenceProvider>
    </AuthProvider>
  );
}



