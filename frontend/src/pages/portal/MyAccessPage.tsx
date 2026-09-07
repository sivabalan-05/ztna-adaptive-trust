import axios from "axios";
import { useCallback, useEffect, useState } from "react";
import {
  blobErrorMessage, getResourceContent, getResources, requestAccess,
  type AccessDecision, type ResourceContent, type ResourceReachability,
} from "../../api/client";
import Page, { Card, Empty } from "../../components/layout/Page";

const TIERS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

const TIER_STYLES: Record<string, string> = {
  PUBLIC: "bg-slate-100 text-slate-700",
  INTERNAL: "bg-sky-50 text-sky-800",
  CONFIDENTIAL: "bg-amber-50 text-amber-800",
  RESTRICTED: "bg-red-50 text-red-800",
};

function humanSize(bytes: number | null): string {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Renders a fetched file: text inline, PDFs and images natively, else save. */
function ContentView({
  content, fileName,
}: {
  content: ResourceContent;
  fileName: string;
}) {
  const [text, setText] = useState<string | null>(null);
  const [url, setUrl] = useState<string>("");

  useEffect(() => {
    const objectUrl = URL.createObjectURL(content.blob);
    setUrl(objectUrl);
    const isText =
      content.contentType.startsWith("text/") ||
      content.contentType === "application/json";
    if (isText) content.blob.text().then(setText);
    else setText(null);
    return () => URL.revokeObjectURL(objectUrl);
  }, [content]);

  return (
    <div className="mt-4">
      {text !== null ? (
        <pre className="max-h-96 overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs text-slate-800">
          {text}
        </pre>
      ) : content.contentType.startsWith("image/") ? (
        <img
          src={url}
          alt={fileName}
          className="max-h-96 rounded-lg border border-slate-200"
        />
      ) : content.contentType === "application/pdf" ? (
        <object
          data={url}
          type="application/pdf"
          className="h-96 w-full rounded-lg border border-slate-200"
        >
          <p className="p-4 text-sm text-slate-600">
            This browser will not display the PDF inline. Use Download instead.
          </p>
        </object>
      ) : (
        <p className="text-sm text-slate-600">
          This file type cannot be previewed. Use Download to save it.
        </p>
      )}

      <a
        href={url}
        download={fileName}
        className="mt-3 inline-block rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
      >
        Download {fileName}
      </a>
    </div>
  );
}

/** The decision the enforcement point returned, shown in full. */
function DecisionPanel({ decision }: { decision: AccessDecision }) {
  // A denial synthesised from 403 headers has no real latency figure — omit
  // the cell rather than print a false "0.0 ms". Granted decisions always
  // carry the server's measured latency.
  const knowsLatency = decision.latency_ms !== null;

  return (
    <div
      className={`mt-4 rounded-lg p-4 text-sm ring-1 ring-inset ${
        decision.granted
          ? "bg-emerald-50 text-emerald-900 ring-emerald-600/20"
          : "bg-red-50 text-red-900 ring-red-600/20"
      }`}
    >
      <div className="font-medium">
        {decision.granted ? "Access granted" : "Access denied"}
      </div>
      <p className="mt-1">{decision.reason}</p>
      <dl
        className={`mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs ${
          knowsLatency ? "sm:grid-cols-4" : "sm:grid-cols-3"
        }`}
      >
        <div>
          <dt className="text-slate-500">Deciding gate</dt>
          <dd className="font-medium">{decision.gate || "—"}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Your score</dt>
          <dd className="font-mono font-medium">{decision.trust_score.toFixed(1)}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Required</dt>
          <dd className="font-mono font-medium">{decision.required_score}</dd>
        </div>
        {knowsLatency && (
          <div>
            <dt className="text-slate-500">Decided in</dt>
            <dd className="font-mono font-medium">
              {decision.latency_ms!.toFixed(1)} ms
            </dd>
          </div>
        )}
      </dl>
      {decision.policies_evaluated.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-slate-600">
            {decision.policies_evaluated.length} policies evaluated
          </summary>
          <ul className="mt-2 space-y-1 text-xs">
            {decision.policies_evaluated.map((policy) => (
              <li key={policy.name} className="flex justify-between gap-4">
                <span className={policy.decisive ? "font-semibold" : ""}>
                  {policy.name} · {policy.effect}
                </span>
                <span className="text-slate-500">
                  {policy.matched ? "matched" : "not matched"}
                  {policy.unmet_conditions.length > 0 &&
                    ` — ${policy.unmet_conditions.join(", ")}`}
                </span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/**
 * What this account can reach right now.
 *
 * Reachability is not a stored property: the server re-scores the session for
 * every entry in this list, so the same catalogue answers differently from a
 * different device, network or hour.
 */
export default function MyAccessPage() {
  const [resources, setResources] = useState<ResourceReachability[]>([]);
  const [openSlug, setOpenSlug] = useState<string>("");
  const [decision, setDecision] = useState<AccessDecision | null>(null);
  const [content, setContent] = useState<ResourceContent | null>(null);
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getResources().then(setResources).catch(() => setResources([]));
  }, []);

  useEffect(load, [load]);

  async function open(resource: ResourceReachability) {
    setOpenSlug(resource.slug);
    setDecision(null);
    setContent(null);
    setError("");
    setBusy(true);
    try {
      setDecision(await requestAccess(resource.slug));
      if (resource.has_file) {
        setContent(await getResourceContent(resource.slug));
      }
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 403) {
        // A denial. Build the same decision shape a grant would have
        // produced, from the response headers plus what we already know
        // about this resource, so DecisionPanel can show the full picture
        // instead of a one-line error.
        const headers = err.response.headers as Record<string, unknown>;
        const gate = typeof headers["x-access-gate"] === "string"
          ? headers["x-access-gate"]
          : "";
        const parsedScore = Number(headers["x-trust-score"]);
        setDecision({
          resource: resource.slug,
          sensitivity: resource.sensitivity,
          granted: false,
          action: resource.action,
          reason: await blobErrorMessage(err, "Access was refused."),
          gate,
          matched_policy: resource.matched_policy,
          required_score: resource.required_score,
          trust_score: Number.isFinite(parsedScore) ? parsedScore : 0,
          risk_level: "",
          latency_ms: null,
          policies_evaluated: [],
        });
      } else {
        setError(await blobErrorMessage(err, "Access was refused."));
      }
    } finally {
      setBusy(false);
      load();
    }
  }

  return (
    <Page
      title="My access"
      description="Every resource is re-evaluated against your live trust score. Opening one is a policy decision, recorded in the audit log."
      actions={
        <button
          onClick={load}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
        >
          Refresh
        </button>
      }
    >
      {resources.length === 0 ? (
        <Empty>No resources are published yet.</Empty>
      ) : (
        TIERS.filter((tier) => resources.some((r) => r.sensitivity === tier)).map(
          (tier) => (
            <div key={tier} className="mb-4">
              <Card title={`${tier.charAt(0)}${tier.slice(1).toLowerCase()}`}>
                <ul className="divide-y divide-slate-100">
                  {resources
                    .filter((resource) => resource.sensitivity === tier)
                    .map((resource) => (
                      <li key={resource.id} className="py-3">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-slate-900">
                                {resource.name}
                              </span>
                              <span
                                className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                                  TIER_STYLES[resource.sensitivity] ?? ""
                                }`}
                              >
                                {resource.sensitivity}
                              </span>
                              <span
                                className={`text-xs ${
                                  resource.reachable
                                    ? "text-emerald-700"
                                    : "text-risk-critical"
                                }`}
                              >
                                {resource.reachable ? "reachable" : "blocked"}
                              </span>
                            </div>
                            <p className="mt-0.5 text-xs text-slate-600">
                              {resource.description}
                            </p>
                            <p className="mt-0.5 text-xs text-slate-400">
                              {resource.owner} · needs {resource.required_score}
                              {resource.has_file
                                ? ` · ${resource.file_name} ${humanSize(resource.file_size)}`
                                : " · no file attached"}
                            </p>
                            {!resource.reachable && (
                              <p className="mt-1 text-xs text-slate-600">
                                {resource.reason}
                              </p>
                            )}
                          </div>
                          <button
                            onClick={() => open(resource)}
                            disabled={busy && openSlug === resource.slug}
                            className="shrink-0 rounded-lg bg-shell px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
                          >
                            {busy && openSlug === resource.slug
                              ? "Checking…"
                              : "Open"}
                          </button>
                        </div>

                        {openSlug === resource.slug && (
                          <>
                            {decision && <DecisionPanel decision={decision} />}
                            {error && (
                              <div className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
                                {error}
                              </div>
                            )}
                            {content && (
                              <ContentView
                                content={content}
                                fileName={resource.file_name ?? resource.slug}
                              />
                            )}
                          </>
                        )}
                      </li>
                    ))}
                </ul>
              </Card>
            </div>
          ),
        )
      )}
    </Page>
  );
}
