import { Fragment, useCallback, useEffect, useState } from "react";
import {
  auditExportUrl, getAudit, tokenStore, verifyChain,
  type AuditRecord, type ChainVerification,
} from "../api/client";
import Page, { Card, Empty } from "../components/layout/Page";

export default function AuditPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [action, setAction] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [check, setCheck] = useState<ChainVerification | null>(null);
  const [checking, setChecking] = useState(false);
  const limit = 50;

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (action) params.set("action", action);
    params.set("limit", String(limit));
    params.set("offset", String(offset));
    getAudit(`?${params}`)
      .then((d) => {
        setRecords(d.records);
        setTotal(d.total);
      })
      .catch(() => setRecords([]));
  }, [query, action, offset]);

  useEffect(load, [load]);

  async function runVerify() {
    setChecking(true);
    try {
      setCheck(await verifyChain());
    } finally {
      setChecking(false);
    }
  }

  /**
   * The export is an authenticated GET, so it cannot be a plain anchor — the
   * browser would send it without the bearer token. Fetch it, then hand the
   * blob to a temporary link.
   */
  async function exportCsv() {
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (action) params.set("action", action);
    const response = await fetch(`${auditExportUrl}?${params}`, {
      headers: { Authorization: `Bearer ${tokenStore.access ?? ""}` },
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "ztna-audit.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Page
      title="Audit logs"
      description="Every security event, hash-linked to the one before it. Altering, inserting or deleting any record breaks every hash after it."
      actions={
        <>
          <button
            onClick={exportCsv}
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-50"
          >
            Export CSV
          </button>
          <button
            onClick={runVerify}
            disabled={checking}
            className="rounded-lg bg-shell px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {checking ? "Verifying…" : "Verify chain"}
          </button>
        </>
      }
    >
      {check && (
        <div
          className={`mb-4 rounded-lg border px-4 py-3 text-sm ${
            check.valid
              ? "border-emerald-200 bg-emerald-50 text-emerald-900"
              : "border-red-200 bg-red-50 text-red-900"
          }`}
        >
          <div className="font-medium">
            {check.valid ? "Chain verified" : "Chain BROKEN"}
          </div>
          <p className="mt-1">
            {check.records_checked.toLocaleString()} records checked in{" "}
            {check.duration_ms.toFixed(0)} ms
            {check.valid
              ? ", unbroken from genesis."
              : ` — first break at position ${check.broken_at}: ${check.reason}.`}
          </p>
          <p className="mt-1 break-all font-mono text-[11px] opacity-70">
            head {check.head_hash}
          </p>
        </div>
      )}

      <div className="mb-4 flex flex-wrap gap-2">
        <input
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOffset(0);
          }}
          placeholder="Search action, actor, resource…"
          className="min-w-64 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
        />
        <select
          value={action}
          onChange={(e) => {
            setAction(e.target.value);
            setOffset(0);
          }}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
          aria-label="Action"
        >
          <option value="">All actions</option>
          {[
            "LOGIN_SUCCESS", "LOGIN_FAILED", "PASSWORD_ACCEPTED", "MFA_FAILED",
            "SESSION_REVOKED", "SESSION_CONTEXT_MISMATCH", "TRUST_EVALUATED",
            "ACCESS_GRANTED", "ACCESS_DENIED", "ALERT_RAISED", "ACCOUNT_LOCKED",
            "DEVICE_APPROVED", "POLICY_CREATED", "USER_UPDATED",
          ].map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>

      <Card>
        {records.length === 0 ? (
          <Empty>No records match.</Empty>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">#</th>
                    <th className="px-3 py-2 font-medium">When</th>
                    <th className="px-3 py-2 font-medium">Actor</th>
                    <th className="px-3 py-2 font-medium">Action</th>
                    <th className="px-3 py-2 font-medium">Resource</th>
                    <th className="px-3 py-2 font-medium">Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {records.map((r) => (
                    <Fragment key={r.seq}>
                      <tr
                        onClick={() =>
                          setExpanded(expanded === r.seq ? null : r.seq)
                        }
                        className="cursor-pointer hover:bg-slate-50"
                      >
                        <td className="px-3 py-2 font-mono text-xs tabular-nums text-slate-500">
                          {r.seq}
                        </td>
                        <td className="px-3 py-2 text-xs text-slate-600">
                          {new Date(r.timestamp).toLocaleString()}
                        </td>
                        <td className="px-3 py-2 text-slate-700">
                          {r.actor_label}
                        </td>
                        <td className="px-3 py-2">
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700">
                            {r.action}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-xs text-slate-600">
                          {r.resource_type}
                          {r.resource_id && ` ${r.resource_id.slice(0, 12)}`}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-400">
                          {r.record_hash.slice(0, 12)}…
                        </td>
                      </tr>
                      {expanded === r.seq && (
                        <tr className="bg-slate-50">
                          <td colSpan={6} className="px-3 py-3">
                            <pre className="overflow-x-auto text-[11px] leading-relaxed text-slate-700">
                              {JSON.stringify(r.payload, null, 2)}
                            </pre>
                            <div className="mt-2 space-y-0.5 font-mono text-[11px] text-slate-500">
                              <div>prev   {r.prev_hash}</div>
                              <div>payload {r.payload_hash}</div>
                              <div>record  {r.record_hash}</div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4 flex items-center justify-between text-sm">
              <span className="text-slate-500">
                {offset + 1}–{Math.min(offset + limit, total)} of{" "}
                {total.toLocaleString()}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                  className="rounded border border-slate-300 px-3 py-1 disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  onClick={() => setOffset(offset + limit)}
                  disabled={offset + limit >= total}
                  className="rounded border border-slate-300 px-3 py-1 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Card>
    </Page>
  );
}
