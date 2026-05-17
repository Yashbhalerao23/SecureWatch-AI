import { FormEvent, useState, useEffect } from 'react';
import { api } from '../../lib/axios';
import Dialog from '../ui/Dialog';
import Input from '../ui/Input';
import Select from '../ui/Select';
import Button from '../ui/Button';
import { UserProfile, UserRole } from '../../types';

export interface EditUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserProfile | null;
  onSuccess: () => void;
}

const EditUserModal: React.FC<EditUserModalProps> = ({ open, onOpenChange, user, onSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    email: '',
    fullName: '',
    role: 'viewer' as UserRole,
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (user) {
      setFormData({
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      });
    }
  }, [user]);

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!formData.email.includes('@')) {
      newErrors.email = 'Invalid email address';
    }
    if (!formData.fullName.trim()) {
      newErrors.fullName = 'Full name is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!validateForm() || !user) return;

    setLoading(true);
    setError('');

    try {
      await api.patch(`/users/${user.id}/`, {
        email: formData.email,
        full_name: formData.fullName,
        role: formData.role,
      });

      onSuccess();
      onOpenChange(false);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update user');
    } finally {
      setLoading(false);
    }
  };

  if (!user) return null;

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Edit User"
      description={`Update details for ${user.username}`}
      size="lg"
      footer={
        <div className="flex gap-3 justify-end">
          <Button variant="secondary" onClick={() => onOpenChange(false)} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={loading}>
            {loading ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="rounded-2xl border border-red-900/30 bg-red-950/20 p-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        <div className="rounded-2xl border border-soc-border bg-slate-900/50 p-4">
          <p className="text-sm text-slate-400">Username</p>
          <p className="text-lg font-semibold text-slate-100">{user.username}</p>
        </div>

        <Input
          label="Email"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          error={errors.email}
          required
          disabled={loading}
        />

        <Input
          label="Full Name"
          value={formData.fullName}
          onChange={(e) => setFormData({ ...formData, fullName: e.target.value })}
          error={errors.fullName}
          required
          disabled={loading}
        />

        <Select
          label="Role"
          options={[
            { value: 'admin', label: 'Admin' },
            { value: 'analyst', label: 'Analyst' },
            { value: 'viewer', label: 'Viewer' },
          ]}
          value={formData.role}
          onChange={(e) => setFormData({ ...formData, role: e.target.value as UserRole })}
          required
          disabled={loading}
        />
      </form>
    </Dialog>
  );
};

export default EditUserModal;
