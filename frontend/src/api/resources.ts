import { api } from "./http";

export interface ResourceSummary {
  id: string;
  slug: string;
  name: string;
  description: string;
  category: string;
  sensitivity: string;
  min_trust_score: number;
  owner: string;
  enabled: boolean;
  has_file: boolean;
  file_name: string | null;
  content_type: string | null;
  file_size: number | null;
}

export interface ResourceReachability extends ResourceSummary {
  reachable: boolean;
  action: string;
  reason: string;
  gate: string;
  required_score: number;
  matched_policy: string;
}

export interface PolicyEvaluation {
  name: string;
  effect: string;
  priority: number;
  matched: boolean;
  decisive: boolean;
  unmet_conditions: string[];
}

export interface AccessDecision {
  resource: string;
  sensitivity: string;
  granted: boolean;
  action: string;
  reason: string;
  gate: string;
  matched_policy: string;
  required_score: number;
  trust_score: number;
  risk_level: string;
  // null on a denial synthesised client-side from 403 headers, where no real
  // figure is available — never render that case as if it were a measured 0.
  latency_ms: number | null;
  policies_evaluated: PolicyEvaluation[];
}

export interface AccessHistoryRow {
  id: string;
  requested_at: string;
  resource: string | null;
  path: string;
  score_at_request: number;
  risk_level: string;
  decision: string;
  granted: boolean;
  reason: string;
  matched_policy: string;
  latency_ms: number;
}

/** A fetched file plus the decision headers that allowed it through. */
export interface ResourceContent {
  blob: Blob;
  contentType: string;
  trustScore: number | null;
}

// --- resources --------------------------------------------------------------

export const getResources = (includeDisabled = false) =>
  api
    .get<ResourceReachability[]>(
      `/api/resources${includeDisabled ? "?include_disabled=true" : ""}`,
    )
    .then((r) => r.data);

export const requestAccess = (slug: string) =>
  api.post<AccessDecision>(`/api/resources/${slug}/access`).then((r) => r.data);

/**
 * Fetches a resource's file. The Authorization header rules out a plain
 * anchor download, so the bytes come back as a blob and the caller decides
 * whether to preview or save them.
 */
export const getResourceContent = (slug: string): Promise<ResourceContent> =>
  api
    .get(`/api/resources/${slug}/content`, { responseType: "blob" })
    .then((r) => ({
      blob: r.data as Blob,
      contentType: String(r.headers["content-type"] ?? "application/octet-stream"),
      trustScore: r.headers["x-trust-score"]
        ? Number(r.headers["x-trust-score"])
        : null,
    }));

export const getAccessHistory = (limit = 50) =>
  api
    .get<AccessHistoryRow[]>(`/api/resources/access/history?limit=${limit}`)
    .then((r) => r.data);

export const createResource = (body: Record<string, unknown>) =>
  api.post<ResourceSummary>("/api/resources", body).then((r) => r.data);

export const updateResource = (slug: string, body: Record<string, unknown>) =>
  api.patch<ResourceSummary>(`/api/resources/${slug}`, body).then((r) => r.data);

export const disableResource = (slug: string) =>
  api.delete(`/api/resources/${slug}`);

export const uploadResourceFile = (slug: string, file: File) => {
  const form = new FormData();
  form.append("file", file);
  return api
    .post<ResourceSummary>(`/api/resources/${slug}/file`, form)
    .then((r) => r.data);
};
