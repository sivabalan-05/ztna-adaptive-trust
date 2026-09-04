import { useCallback, useEffect, useState } from "react";
import { getSessions, revokeSession, verifyNow, type LiveSession } from "../api/client";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";
import { useLive } from "../live/LiveContext";

/**
 * Live session table.
 *
 * Rows update from the WebSocket rather than from polling: the verification
 * sweep pushes a score for every session it re-evaluates, so a row changes
 * here at the moment the engine changes its mind — not on the next refresh.
 */
export default function LiveMonitoringPage() {
  const [rows, setRows] = useState<LiveSession[]>([]);
  const [flash, setFlash] = useState<Record<string, number>>({});
  const [busy, setBusy] = useState(false);
  const { lastEvent, status } = useLive();

  const load = useCallback(() => {
    getSessions().then(setRows).catch(() => setRows([]));
  }, []);

  useEffect(load, [load]);

  useEffect(() => {
    if (!lastEvent) return;

    if (lastEvent.type === "session.score") {
      const p = lastEvent.payload as Record<string, unknown>;
      const id = String(p.session_id);
      setRows((current) =>
        current.map((row) =>
          row.id === id
            ? {
                ...row,
                current_trust_score: Number(p.score),
                current_risk_level: String(p.risk_level),
                current_action: String(p.action),
                last_verified_at: lastEvent.at,
              }
            : row,
        ),
      );
      setFlash((f) => ({ ...f, [id]: Date.now() }));
    }

    if (
      lastEvent.type === "session.revoked" ||
      lastEvent.type === "session.expired"
    ) {
      const id = String((lastEvent.payload as Record<string, unknown>).session_id);
      setRows((current) => current.filter((row) => row.id !== id));
    }
  }, [lastEvent]);

  async function kill(row: LiveSession) {
    const reason = window.prompt(
      `Revoke ${row.username}'s session? Give a reason — it is written to the audit chain.`,
      "Revoked by an administrator.",
    );
    if (!reason) return;
    await revokeSession(row.id, reason);
    setRows((current) => current.filter((r) => r.id !== row.id));
  }

  async function sweep() {
    setBusy(true);
    try {
      await verifyNow();
      load();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Page
      title="Live monitoring"
      description="Active sessions with their current trust score. Rows update as the verification sweep re-scores them — no refresh."
      actions={
        <>
          <span className="text-xs text-slate-500">stream {status}</span>
          <button
            onClick={sweep}
            disabled={busy}
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-50 disabled:opacity-50"
          >
            {busy ? "Sweeping…" : "Run sweep now"}
          </button>
        </>
      }
    >
      <Card>
        {rows.length === 0 ? (
          <Empty>No active sessions.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Trust</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                  <th className="px-3 py-2 font-medium">Where</th>
                  <th className="px-3 py-2 font-medium">Device</th>
                  <th className="px-3 py-2 font-medium">Verified</th>
                  <th className="px-3 py-2 font-medium">Requests</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {rows.map((row) => {
                  const recent = Date.now() - (flash[row.id] ?? 0) < 2500;
                  return (
                    <tr
                      key={row.id}
                      className={recent ? "bg-blue-50/60 transition-colors" : "transition-colors"}
                    >
                      <td className="px-3 py-2.5">
                        <div className="font-medium text-slate-900">
                          {row.username}
                        </div>
                        <div className="text-xs text-slate-500">{row.role}</div>
                      </td>
                      <td className="px-3 py-2.5">
                        <RiskChip
                          level={row.current_risk_level}
                          score={row.current_trust_score}
                        />
                      </td>
                      <td className="px-3 py-2.5 text-slate-600">
                        {row.current_action.replace(/_/g, " ").toLowerCase()}
                      </td>
                      <td className="px-3 py-2.5">
                        <div className="text-slate-700">
                          {row.city || "—"}, {row.country}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {row.ip_address}
                          {row.is_vpn && (
                            <span className="ml-1 text-risk-high">VPN</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        <div className="text-slate-700">
                          {row.device_label ?? "—"}
                        </div>
                        <div className="text-[11px] text-slate-500">
                          {row.device_status}
                        </div>
                      </td>
                      <td className="px-3 py-2.5 text-xs text-slate-600">
                        {row.last_verified_at
                          ? new Date(row.last_verified_at).toLocaleTimeString()
                          : "—"}
                      </td>
                      <td className="px-3 py-2.5 tabular-nums text-slate-600">
                        {row.request_count}
                        {row.denied_count > 0 && (
                          <span className="ml-1 text-risk-critical">
                            ({row.denied_count} denied)
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <button
                          onClick={() => kill(row)}
                          className="rounded border border-red-200 px-2.5 py-1 text-xs text-risk-critical hover:bg-red-50"
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Page>
  );
}
