export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface UserProfile {
  id: number;
  username: string;
  fullName: string;
  email: string;
  role: UserRole;
  status?: 'active' | 'disabled' | 'locked';
  last_login?: string;
  trusted_devices?: number;
  risk_score?: number;
}

export interface MetricCardData {
  label: string;
  value: string | number;
  description: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success';
}

export interface LogEvent {
  id: number;
  timestamp: string;
  event_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  hostname: string;
  user: string;
  message: string;
  raw_data?: string;
  // AI Fields
  analyzed?: boolean;
  ai_threat_detected?: boolean;
  ai_threat_type?: string;
  ai_severity?: string;
  ai_analysis?: {
    description?: string;
    recommendation?: string;
    confidence?: number;
  };
}

export interface AlertItem {
  id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  hostname: string;
  event_id?: number;
  ai_score?: number;
  status: 'new' | 'acknowledged' | 'resolved' | 'false_positive';
  created_at: string;
}

export interface EndpointItem {
  id: number;
  hostname: string;
  ip_address: string;
  os: string;
  last_seen: string;
  status: 'online' | 'offline' | 'warning';
  risk_score: number;
  total_alerts: number;
}

export interface AuditEventItem {
  id: number;
  user: string;
  action: string;
  target: string;
  ip_address: string;
  device: string;
  device_fingerprint?: string;
  browser?: string;
  created_at: string;
}

export interface AnalysisItem {
  id: number;
  title: string;
  score: number;
  category: string;
  summary: string;
  recommendation: string;
  related_log_ids: number[];
}
