import { useEffect, useState } from 'react';
import { api } from '../lib/axios';
import { UserProfile } from '../types';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import CreateUserModal from '../components/modals/CreateUserModal';
import EditUserModal from '../components/modals/EditUserModal';
import Spinner from '../components/ui/Spinner';

export default function UserManagement() {
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserProfile | null>(null);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const response = await api.get<any>('/users/');
      if (response.data && response.data.results) {
        setUsers(response.data.results);
      } else if (Array.isArray(response.data)) {
        setUsers(response.data);
      } else {
        setUsers([]);
      }
    } catch (error) {
      console.error("Failed to fetch users:", error);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchUsers();
  }, []);

  const handleEditClick = (user: UserProfile) => {
    setSelectedUser(user);
    setEditModalOpen(true);
  };

  const handleDeleteUser = async (user: UserProfile) => {
    if (!window.confirm(`Are you sure you want to delete operator ${user.username}? This action cannot be undone.`)) {
      return;
    }

    try {
      await api.delete(`/users/${user.id}/`);
      setUsers(users.filter(u => u.id !== user.id));
      alert("Operator deleted successfully.");
    } catch (error) {
      console.error("Delete failed:", error);
      alert("Failed to delete user. Check permissions.");
    }
  };

  const handleEditSuccess = () => {
    void fetchUsers();
    setSelectedUser(null);
  };

  return (
    <div className="max-w-[1600px] mx-auto space-y-6 pb-12">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between px-2">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-tight">Identity & Access</h2>
          <p className="mt-1 text-slate-400">Manage SOC operators, administrative roles, and system access controls.</p>
        </div>
        <Button 
          onClick={() => setCreateModalOpen(true)}
          className="shadow-lg shadow-soc-accent/20"
        >
          Add New Operator
        </Button>
      </div>

      <div className="panel-card overflow-hidden border-t-0">
        <div className="overflow-x-auto">
          <table className="min-w-full border-separate border-spacing-0 text-sm">
            <thead className="bg-slate-950/95 text-slate-500 font-bold uppercase tracking-widest text-[10px]">
              <tr>
                <th className="px-6 py-4 text-left border-b border-white/5">Operator</th>
                <th className="px-6 py-4 text-left border-b border-white/5">Contact</th>
                <th className="px-6 py-4 text-left border-b border-white/5">Role</th>
                <th className="px-6 py-4 text-left border-b border-white/5">Status</th>
                <th className="px-6 py-4 text-left border-b border-white/5">Last Active</th>
                <th className="px-6 py-4 text-right border-b border-white/5">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-slate-900/20">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-20 text-center">
                    <Spinner size="md" text="Syncing user database..." />
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-20 text-center text-slate-500 italic">
                    No active operators found in the registry.
                  </td>
                </tr>
              ) : users.map((user) => (
                <tr key={user.id} className="group border-t border-white/5 hover:bg-white/5 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex flex-col">
                      <span className="font-semibold text-white">{user.fullName || user.username}</span>
                      <span className="text-[11px] text-slate-500 font-mono">@{user.username}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-slate-400">{user.email || 'N/A'}</td>
                  <td className="px-6 py-4">
                    <Badge variant="info" className="text-[10px] uppercase font-bold px-2 py-0.5 border border-blue-500/20 bg-blue-500/5">
                      {user.role}
                    </Badge>
                  </td>
                  <td className="px-6 py-4">
                    <Badge variant={user.status === 'disabled' ? 'high' : 'success'}>
                      {user.status || 'active'}
                    </Badge>
                  </td>
                  <td className="px-6 py-4 text-slate-400 font-mono text-xs">
                    {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => handleEditClick(user)} className="text-xs group-hover:bg-soc-accent/10">
                        Manage
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => handleDeleteUser(user)} className="text-xs group-hover:bg-red-500/10 text-slate-500 hover:text-red-500">
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <CreateUserModal open={createModalOpen} onOpenChange={setCreateModalOpen} onSuccess={fetchUsers} />
      <EditUserModal open={editModalOpen} onOpenChange={setEditModalOpen} user={selectedUser} onSuccess={handleEditSuccess} />
    </div>
  );
}
