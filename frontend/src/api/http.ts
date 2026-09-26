import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { collectDeviceSignals } from "../lib/fingerprint";

const configuredApiUrl =
  import.meta.env.VITE_API_URL?.trim() ||
  import.meta.env.VITE_API_BASE_URL?.trim() ||
  "http://localhost:8000";
const parsedApiUrl = new URL(configuredApiUrl);

if (parsedApiUrl.protocol !== "http:" && parsedApiUrl.protocol !== "https:") {
  throw new Error("VITE_API_URL must use http or https.");
}

export const baseURL = parsedApiUrl.toString().replace(/\/+$/, "");

export const api = axios.create({
  baseURL,
  timeout: 15_000,
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

/**
 * Reads the `detail` out of a failed blob request. A denial's reason arrives
 * as a Blob rather than parsed JSON, so it needs decoding before display.
 */
export async function blobErrorMessage(
  error: unknown,
  fallback: string,
): Promise<string> {
  if (axios.isAxiosError(error) && error.response?.data instanceof Blob) {
    try {
      const parsed = JSON.parse(await error.response.data.text());
      if (parsed?.detail) return String(parsed.detail);
    } catch {
      /* not JSON; fall through to the generic message */
    }
  }
  return apiErrorMessage(error, fallback);
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
