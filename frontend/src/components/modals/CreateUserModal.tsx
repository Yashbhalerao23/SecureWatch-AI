import { FormEvent, useState } from 'react';
import { api } from '../../lib/axios';
import Dialog from '../ui/Dialog';
import Input from '../ui/Input';
import Select from '../ui/Select';
import Button from '../ui/Button';
import { UserRole } from '../../types';

export interface CreateUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

const CreateUserModal: React.FC<CreateUserModalProps> = ({ open, onOpenChange, onSuccess }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    fullName: '',
    password: '',
    confirmPassword: '',
    role: 'viewer' as UserRole,
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!formData.email.includes('@')) {
      newErrors.email = 'Invalid email address';
    }
    if (!formData.fullName.trim()) {
      newErrors.fullName = 'Full name is required';
    }
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    }
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);
    setError('');

    try {
      await api.post('/users/', {
        username: formData.username,
        email: formData.email,
        full_name: formData.fullName,
        password: formData.password,
        role: formData.role,
      });

      onSuccess();
      onOpenChange(false);
      setFormData({
        username: '',
        email: '',
        fullName: '',
        password: '',
        confirmPassword: '',
        role: 'viewer',
      });
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create user');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Create New User"
      description="Add a new user to the security monitoring system"
      size="lg"
      footer={
        <div className="flex gap-3 justify-end">
          <Button variant="secondary" onClick={() => onOpenChange(false)} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={loading}>
            {loading ? 'Creating...' : 'Create User'}
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

        <Input
          label="Username"
          placeholder="john_doe"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          error={errors.username}
          required
          disabled={loading}
        />

        <Input
          label="Email"
          type="email"
          placeholder="john@example.com"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          error={errors.email}
          required
          disabled={loading}
        />

        <Input
          label="Full Name"
          placeholder="John Doe"
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

        <Input
          label="Password"
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
          error={errors.password}
          required
          disabled={loading}
        />

        <Input
          label="Confirm Password"
          type="password"
          value={formData.confirmPassword}
          onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
          error={errors.confirmPassword}
          required
          disabled={loading}
        />
      </form>
    </Dialog>
  );
};

export default CreateUserModal;
