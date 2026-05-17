import FingerprintJS, { type Agent } from '@fingerprintjs/fingerprintjs';

export type FingerprintSessionMetadata = {
  deviceId: string;
  browser: string;
  os: string;
  timezone: string;
  screen: { width: number; height: number; devicePixelRatio: number };
  userAgent: string;
  locale?: string;
};

function safeJsonParse<T>(value: string | null): T | null {
  if (!value) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

const SESSION_DEVICE_KEY = 'soc_device_id';

export async function getOrCreateDeviceFingerprint(): Promise<FingerprintSessionMetadata> {
  const existing = safeJsonParse<FingerprintSessionMetadata>(
    typeof window !== 'undefined' ? window.sessionStorage.getItem('soc_device_metadata') : null
  );

  if (existing?.deviceId) return existing;

  // Generate stable fingerprint (server-side storage/validation recommended)
  const fp: Agent = await FingerprintJS.load();
  const result = await fp.get();

  const nav = typeof navigator !== 'undefined' ? navigator : ({} as Navigator);
  const screenObj = typeof screen !== 'undefined' ? screen : ({} as Screen);

  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  const uaData: any = (nav as any).userAgentData;

  const meta: FingerprintSessionMetadata = {
    deviceId: String(result.visitorId),
    browser: uaData?.brands?.map((b: any) => b.brand).join(', ') || nav.userAgent,
    os: uaData?.platform || 'unknown',
    timezone,
    screen: {
      width: (screenObj as any).width ?? 0,
      height: (screenObj as any).height ?? 0,
      devicePixelRatio: (typeof window !== 'undefined' && window.devicePixelRatio) || 1
    },
    userAgent: nav.userAgent || '',
    locale: nav.language
  };

  if (typeof window !== 'undefined') {
    // sessionStorage keeps it in-session; backend can permanently record the fingerprint.
    window.sessionStorage.setItem('soc_device_metadata', JSON.stringify(meta));
    window.sessionStorage.setItem(SESSION_DEVICE_KEY, meta.deviceId);
  }

  return meta;
}

export async function collectLoginMetadataForBackend(): Promise<FingerprintSessionMetadata> {
  return getOrCreateDeviceFingerprint();
}

