import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/axios';
import { collectLoginMetadataForBackend, type FingerprintSessionMetadata } from '../services/fingerprint';

export type SessionIntelligence = {
  deviceId: string;
  lastLoginAt?: string;
  deviceStatus?: 'trusted' | 'new' | 'suspicious';
  browserChanged?: boolean;
  osChanged?: boolean;
  unusualLocation?: boolean;
};

type Ctx = {
  deviceMetadata: FingerprintSessionMetadata | null;
  intelligence: SessionIntelligence | null;
  loading: boolean;
  refresh: () => Promise<void>;
  collectLoginMetadataForBackend: typeof collectLoginMetadataForBackend;
};

const SessionIntelligenceContext = createContext<Ctx | undefined>(undefined);

export function SessionIntelligenceProvider({ children }: { children: React.ReactNode }) {
  const [deviceMetadata, setDeviceMetadata] = useState<FingerprintSessionMetadata | null>(null);
  const [intelligence, setIntelligence] = useState<SessionIntelligence | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    setLoading(true);
    try {
      const metadata = await collectLoginMetadataForBackend();
      setDeviceMetadata(metadata);

      // Backend endpoint is assumed per requirement; implement if missing.
      const resp = await api.post<SessionIntelligence>('/auth/session-intelligence/', {
        device_fingerprint: metadata.deviceId,
        metadata
      });

      setIntelligence(resp.data);
    } catch (e) {
      // UI should remain usable even if backend doesn't support yet.
      setIntelligence(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo(() => ({ deviceMetadata, intelligence, loading, refresh, collectLoginMetadataForBackend }), [deviceMetadata, intelligence, loading]);

  return <SessionIntelligenceContext.Provider value={value}>{children}</SessionIntelligenceContext.Provider>;
}

export function useSessionIntelligence() {
  const ctx = useContext(SessionIntelligenceContext);
  if (!ctx) throw new Error('useSessionIntelligence must be used inside SessionIntelligenceProvider');
  return ctx;
}

