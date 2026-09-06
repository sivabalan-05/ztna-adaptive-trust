import { api } from "./http";

export interface PolicyRow {
  id: string;
  name: string;
  description: string;
  role: string | null;
  resource: string | null;
  sensitivity: string | null;
  min_trust_score: number;
  require_mfa: boolean;
  require_known_device: boolean;
  deny_vpn: boolean;
  allowed_countries: string[];
  time_window: Record<string, unknown>;
  effect: string;
  priority: number;
  enabled: boolean;
}

// --- policies ---------------------------------------------------------------

export const getPolicies = () =>
  api.get<PolicyRow[]>("/api/policies").then((r) => r.data);

export const createPolicy = (body: Record<string, unknown>) =>
  api.post<PolicyRow>("/api/policies", body).then((r) => r.data);

export const updatePolicy = (id: string, body: Record<string, unknown>) =>
  api.patch<PolicyRow>(`/api/policies/${id}`, body).then((r) => r.data);

export const deletePolicy = (id: string) => api.delete(`/api/policies/${id}`);
