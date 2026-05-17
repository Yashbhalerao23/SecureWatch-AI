import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useSessionIntelligence } from '../context/SessionIntelligenceContext';
import { api } from '../lib/axios';
import Button from '../components/ui/Button';
import Spinner from '../components/ui/Spinner';
import Badge from '../components/ui/Badge';

export default function Login() {
  const { user, refreshUserWithToken, setAuthToken, setRefreshToken } = useAuth();
  const { collectLoginMetadataForBackend } = useSessionIntelligence();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [collectingFingerprint, setCollectingFingerprint] = useState(false);
  const [fingerprintData, setFingerprintData] = useState<{
    deviceId?: string;
    browser?: string;
    os?: string;
    timezone?: string;
  } | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (user) {
      navigate('/', { replace: true });
    }
  }, [user, navigate]);

  useEffect(() => {
    const collectFingerprint = async () => {
      setCollectingFingerprint(true);
      try {
        const metadata = await collectLoginMetadataForBackend();
        if (metadata) {
          setFingerprintData({
            deviceId: metadata.deviceId?.substring(0, 8) + '...',
            browser: metadata.browser || 'Unknown',
            os: metadata.os || 'Unknown',
            timezone: metadata.timezone,
          });
        }
      } catch (err) {
        console.error('Fingerprint collection failed:', err);
      } finally {
        setCollectingFingerprint(false);
      }
    };

    collectFingerprint();
  }, [collectLoginMetadataForBackend]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      const metadata = await collectLoginMetadataForBackend();
      const response = await api.post('/auth/login/', {
        username,
        password,
        login_intelligence: {
          device_fingerprint: metadata.deviceId,
          browser: metadata.browser,
          os: metadata.os,
          timezone: metadata.timezone,
          user_agent: metadata.userAgent,
          locale: metadata.locale,
          screen: metadata.screen,
          login_timestamp: new Date().toISOString()
        }
      });
      const token = response.data.access ?? response.data.token;
      const refresh = response.data.refresh ?? response.data.refresh_token;
      setAuthToken(token);
      setRefreshToken(refresh ?? null);
      if (token) {
        await refreshUserWithToken(token);
      }
      navigate('/', { replace: true });
    } catch (exc) {
      setError('Invalid credentials or authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid min-h-screen place-items-center bg-soc-surface px-4 py-12">
      <div className="w-full max-w-md space-y-4">
        {/* Device Fingerprint Card */}
        {collectingFingerprint ? (
          <div className="rounded-3xl border border-soc-border bg-slate-900/50 p-6">
            <div className="flex items-center gap-3">
              <Spinner size="sm" />
              <div>
                <p className="text-sm font-medium text-slate-300">Verifying device...</p>
                <p className="text-xs text-slate-500 mt-1">Collecting security fingerprint</p>
              </div>
            </div>
          </div>
        ) : fingerprintData ? (
          <div className="rounded-3xl border border-emerald-900/30 bg-emerald-950/20 p-4">
            <div className="flex items-center gap-2 mb-3">
              <Badge variant="success">Device Verified</Badge>
              <span className="text-xs text-emerald-400">Security check passed</span>
            </div>
            <div className="space-y-2 text-xs text-slate-400">
              <div className="flex justify-between">
                <span>Device:</span>
                <span className="font-mono text-slate-300">{fingerprintData.deviceId}</span>
              </div>
              <div className="flex justify-between">
                <span>Browser:</span>
                <span className="text-slate-300">{fingerprintData.browser}</span>
              </div>
              <div className="flex justify-between">
                <span>OS:</span>
                <span className="text-slate-300">{fingerprintData.os}</span>
              </div>
              <div className="flex justify-between">
                <span>Timezone:</span>
                <span className="text-slate-300">{fingerprintData.timezone}</span>
              </div>
            </div>
          </div>
        ) : null}

        {/* Login Form */}
        <div className="rounded-3xl border border-soc-border bg-slate-950/95 p-8 shadow-panel">
          <h1 className="text-3xl font-semibold text-white">SOC Login</h1>
          <p className="mt-2 text-sm text-slate-400">
            Access the security monitoring console with your SOC credentials.
          </p>

          <form onSubmit={handleSubmit} className="mt-8 space-y-4">
            <label className="block text-sm text-slate-300">
              Username
              <input
                className="mt-2 w-full rounded-2xl border border-soc-border bg-slate-900/95 px-4 py-3 text-sm text-slate-100 outline-none focus:border-soc-accent focus:ring-1 focus:ring-soc-accent"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
                disabled={loading}
              />
            </label>

            <label className="block text-sm text-slate-300">
              Password
              <input
                type="password"
                className="mt-2 w-full rounded-2xl border border-soc-border bg-slate-900/95 px-4 py-3 text-sm text-slate-100 outline-none focus:border-soc-accent focus:ring-1 focus:ring-soc-accent"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                disabled={loading}
              />
            </label>

            {error && (
              <div className="rounded-2xl border border-red-900/30 bg-red-950/20 p-3">
                <p className="text-sm text-red-400">{error}</p>
              </div>
            )}

            <Button type="submit" disabled={loading} className="w-full">
              {loading ? (
                <>
                  <span className="inline-block mr-2">
                    <Spinner size="sm" />
                  </span>
                  Authenticating…
                </>
              ) : (
                'Sign in'
              )}
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}
