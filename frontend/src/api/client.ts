import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { collectDeviceSignals } from "../lib/fingerprint";

const baseURL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export const api = axios.create({
  baseURL,
  timeout: 15_000,
  headers: { "Content-Type": "application/json" },
});

/**
 * Tokens live in sessionStorage: cleared when the tab closes, and not shared
 * with other tabs or windows. A production deployment would move the refresh
 * token into an httpOnly, SameSite=Strict cookie so that script running on the
 * page cannot read it at all; sessionStorage is the demo-friendly middle ground.
 */
const ACCESS_KEY = "ztna.access";
const REFRESH_KEY = "ztna.refresh";

export const tokenStore = {
  get access(): string | null {
    return sessionStorage.getItem(ACCESS_KEY);
  },
  get refresh(): string | null {
    return sessionStorage.getItem(REFRESH_KEY);
  },
  set(access: string, refresh: string) {
    sessionStorage.setItem(ACCESS_KEY, access);
    sessionStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    sessionStorage.removeItem(ACCESS_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
  },
};

api.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  const signals = await collectDeviceSignals();
  config.headers.set("X-Device-Fingerprint", signals.fingerprint);
  config.headers.set("X-Device-Platform", signals.platform);
  config.headers.set("X-Device-Screen", signals.screen);
  config.headers.set("X-Device-Timezone", signals.timezone);

  const token = tokenStore.access;
  if (token && !config.headers.has("Authorization")) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

let refreshing: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  const refresh = tokenStore.refresh;
  if (!refresh) return null;
  try {
    const { data } = await axios.post<TokenResponse>(
      `${baseURL}/api/auth/refresh`,
      { refresh_token: refresh },
      { headers: { "Content-Type": "application/json" } },
    );
    tokenStore.set(data.access_token, data.refresh_token);
    return data.access_token;
  } catch {
    tokenStore.clear();
    return null;
  }
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & {
      _retried?: boolean;
    };
    const status = error.response?.status;
    const wwwAuth = String(error.response?.headers?.["www-authenticate"] ?? "");

    // Only a genuinely expired access token is worth retrying. A revoked
    // session, a device mismatch or a missing MFA step must surface to the
    // user immediately — silently refreshing past them would defeat the point.
    const retryable = status === 401 && wwwAuth.includes("token_expired");

    if (retryable && original && !original._retried) {
      original._retried = true;
      refreshing ??= refreshAccessToken().finally(() => {
        refreshing = null;
      });
      const token = await refreshing;
      if (token) {
        original.headers.set("Authorization", `Bearer ${token}`);
        return api(original);
      }
    }
    return Promise.reject(error);
  },
);

export function apiErrorMessage(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error)) {
    const detail = (error.response?.data as { detail?: string } | undefined)?.detail;
    if (detail) return detail;
    if (!error.response) return "Cannot reach the API. Is the backend running?";
  }
  return fallback;
}

// --- types ------------------------------------------------------------------

export interface Health {
  status: "ok" | "degraded";
  app: string;
  version: string;
  environment: string;
  database: string;
  database_reachable: boolean;
  cache: string;
  tables: number;
  time: string;
}

export interface LoginChallenge {
  mfa_required: boolean;
  mfa_token: string;
  expires_in: number;
  session_id: string;
  device_known: boolean;
  device_status: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  session_id: string;
  username?: string;
  full_name?: string;
  role?: string;
  is_admin?: boolean;
  permissions?: string[];
  device_status?: string;
  device_approved?: boolean;
}

export interface SessionInfo {
  id: string;
  status: string;
  ip_address: string;
  city: string;
  country: string;
  started_at: string;
  last_seen_at: string;
  expires_at: string;
  mfa_passed: boolean;
  step_up_required: boolean;
  current_trust_score: number;
  current_risk_level: string;
  current_action: string;
  request_count: number;
  revoked_reason: string;
}

export interface DeviceInfo {
  id: string;
  label: string;
  fingerprint: string;
  status: string;
  os: string;
  browser: string;
  is_trusted: boolean;
  seen_count: number;
  first_seen_at: string;
  last_seen_at: string;
  approved_at: string | null;
}

export interface TrustFactor {
  factor: string;
  weight: number;
  penalty: number;
  points_deducted: number;
  reason: string;
  reasons: string[];
  signals: Record<string, unknown>;
}

export interface TrustScore {
  id: string;
  session_id: string;
  user_id: string;
  score: number;
  risk_level: string;
  action: string;
  trigger: string;
  anomaly_score: number | null;
  reason: string;
  factors: TrustFactor[];
  created_at: string;
}

export interface TrustAssessment {
  score: number;
  weighted_score: number;
  risk_level: string;
  action: string;
  anomaly_score: number | null;
  headline: string;
  narrative: string;
  total_deducted: number;
  was_overridden: boolean;
  applied_overrides: string[];
  factors: TrustFactor[];
  weights: Record<string, number>;
}

export interface RiskBand {
  level: string;
  min: number;
  max: number;
  description: string;
}

export interface TrustConfig {
  weights: Record<string, number>;
  bands: RiskBand[];
  sensitivity_floors: Record<string, number>;
  overrides: { name: string; clamps_to: number; reason: string }[];
  anomaly_model_available: boolean;
  continuous_verification_interval_seconds: number;
}

export interface Me {
  id: string;
  username: string;
  email: string;
  full_name: string;
  department: string;
  role: string;
  is_admin: boolean;
  permissions: string[];
  mfa_enabled: boolean;
  account_status: string;
  last_login_at: string | null;
  home_city: string;
  home_country: string;
  session: SessionInfo;
  device: DeviceInfo | null;
}

// --- calls ------------------------------------------------------------------

export const getHealth = () => api.get<Health>("/health").then((r) => r.data);

export const login = (username: string, password: string) =>
  api
    .post<LoginChallenge>("/api/auth/login", { username, password })
    .then((r) => r.data);

export const verifyMfa = (mfa_token: string, code: string) =>
  api
    .post<TokenResponse>("/api/auth/mfa/verify", { mfa_token, code })
    .then((r) => r.data);

export const getMe = () => api.get<Me>("/api/auth/me").then((r) => r.data);

export const getMyDevices = () =>
  api.get<DeviceInfo[]>("/api/devices/me").then((r) => r.data);

export const logout = () => api.post("/api/auth/logout");

export const getMyTrust = () =>
  api.get<TrustScore>("/api/trust/me").then((r) => r.data);

export const evaluateMyTrust = () =>
  api.post<TrustAssessment>("/api/trust/me/evaluate").then((r) => r.data);

export const getTrustConfig = () =>
  api.get<TrustConfig>("/api/trust/config").then((r) => r.data);

export interface WsTicket {
  ticket: string;
  expires_in: number;
  url: string;
}

export const getWsTicket = () =>
  api.post<WsTicket>("/api/ws/ticket").then((r) => r.data);

export interface LiveEvent {
  type:
    | "connected"
    | "heartbeat"
    | "session.score"
    | "session.revoked"
    | "session.expired"
    | "session.terminated";
  at: string;
  payload: Record<string, unknown>;
}

// --- admin, alerts, dashboard, sessions -------------------------------------

export interface UserRow {
  id: string;
  username: string;
  email: string;
  full_name: string;
  department: string;
  role: string;
  is_admin: boolean;
  account_status: string;
  is_locked: boolean;
  mfa_enabled: boolean;
  mfa_enrolled: boolean;
  last_login_at: string | null;
  failed_login_count: number;
  home_city: string;
  home_country: string;
  device_count: number;
  active_sessions: number;
  latest_trust_score: number | null;
  latest_risk_level: string | null;
}

export interface RoleRow {
  name: string;
  description: string;
  is_admin: boolean;
  max_sensitivity_ordinal: number;
  permissions: string[];
  user_count: number;
}

export interface AlertRow {
  id: string;
  severity: string;
  status: string;
  category: string;
  title: string;
  description: string;
  trust_score: number | null;
  evidence: Record<string, unknown>;
  user_id: string | null;
  username: string | null;
  session_id: string | null;
  created_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_note: string;
}

export interface LiveSession {
  id: string;
  user_id: string;
  username: string;
  full_name: string;
  role: string;
  status: string;
  ip_address: string;
  city: string;
  country: string;
  is_vpn: boolean;
  device_label: string | null;
  device_status: string | null;
  started_at: string;
  last_seen_at: string;
  last_verified_at: string | null;
  expires_at: string;
  current_trust_score: number;
  current_risk_level: string;
  current_action: string;
  mfa_passed: boolean;
  step_up_required: boolean;
  request_count: number;
  denied_count: number;
  revoked_reason: string;
}

export interface Overview {
  active_sessions: number;
  average_trust_score: number | null;
  alerts_today: number;
  open_alerts: number;
  blocked_attempts_today: number;
  total_users: number;
  locked_users: number;
  pending_devices: number;
  risk_distribution: { level: string; count: number }[];
  trust_over_time: { at: string; score: number; risk_level: string }[];
  recent_alerts: AlertRow[];
  verification_interval_seconds: number;
  anomaly_model_version: string | null;
  audit_records: number;
}

export interface AuditRecord {
  seq: number;
  id: string;
  timestamp: string;
  actor_id: string | null;
  actor_label: string;
  action: string;
  resource_type: string;
  resource_id: string;
  ip_address: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  prev_hash: string;
  record_hash: string;
  note: string;
}

export interface ChainVerification {
  valid: boolean;
  records_checked: number;
  broken_at: number | null;
  reason: string | null;
  head_hash: string;
  partial: boolean;
  verified_from: number;
  duration_ms: number;
  genesis_hash: string;
  checked_at: string;
}

export interface TrustHistoryPoint {
  at: string;
  score: number;
  risk_level: string;
  action: string;
  trigger: string;
  reason: string;
}

export const getOverview = (hours = 24) =>
  api.get<Overview>(`/api/dashboard/overview?hours=${hours}`).then((r) => r.data);

export const getUsers = (q = "") =>
  api
    .get<UserRow[]>(`/api/users${q ? `?q=${encodeURIComponent(q)}` : ""}`)
    .then((r) => r.data);

export const getRoles = () =>
  api.get<RoleRow[]>("/api/users/roles").then((r) => r.data);

export const updateUser = (id: string, body: Record<string, unknown>) =>
  api.patch<UserRow>(`/api/users/${id}`, body).then((r) => r.data);

export const getAllDevices = (status?: string) =>
  api
    .get<DeviceInfo[]>(`/api/devices${status ? `?status=${status}` : ""}`)
    .then((r) => r.data);

export const approveDevice = (id: string) =>
  api.post<DeviceInfo>(`/api/devices/${id}/approve`).then((r) => r.data);

export const revokeDevice = (id: string) =>
  api.post<DeviceInfo>(`/api/devices/${id}/revoke`).then((r) => r.data);

export const getSessions = () =>
  api.get<LiveSession[]>("/api/sessions").then((r) => r.data);

export const revokeSession = (id: string, reason: string) =>
  api
    .post<LiveSession>(`/api/sessions/${id}/revoke`, { reason })
    .then((r) => r.data);

export const verifyNow = () =>
  api.post("/api/sessions/verify-now").then((r) => r.data);

export const getAlerts = (params = "") =>
  api
    .get<{ total: number; alerts: AlertRow[] }>(`/api/alerts${params}`)
    .then((r) => r.data);

export const acknowledgeAlert = (id: string) =>
  api.post<AlertRow>(`/api/alerts/${id}/acknowledge`).then((r) => r.data);

export const resolveAlert = (id: string, note: string) =>
  api.post<AlertRow>(`/api/alerts/${id}/resolve`, { note }).then((r) => r.data);

export const getAudit = (params = "") =>
  api
    .get<{ total: number; records: AuditRecord[] }>(`/api/audit${params}`)
    .then((r) => r.data);

export const verifyChain = () =>
  api.get<ChainVerification>("/api/audit/verify").then((r) => r.data);

export const auditExportUrl = `${baseURL}/api/audit/export.csv`;

export const getUserTrustHistory = (userId: string) =>
  api
    .get<TrustHistoryPoint[]>(`/api/trust/users/${userId}/history`)
    .then((r) => r.data);

export const getSessionTrust = (sessionId: string) =>
  api.get<TrustScore>(`/api/trust/sessions/${sessionId}`).then((r) => r.data);

export const getSessionTrustHistory = (sessionId: string) =>
  api
    .get<TrustHistoryPoint[]>(`/api/trust/sessions/${sessionId}/history`)
    .then((r) => r.data);

export const wsBaseUrl =
  import.meta.env.VITE_WS_BASE_URL ??
  baseURL.replace(/^http/, "ws");
