import { useCallback, useEffect, useState } from "react";
import { getSessions, revokeSession, type LiveSession } from "../api/client";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";
import { useLive } from "../live/LiveContext";

export default function RevocationPage() {
  const [rows, setRows] = useState<LiveSession[]>([]);
  const [selected, setSelected] = useState<LiveSession | null>(null);
  const [reason, setReason] = useState("Revoked by an administrator.");
  const [result, setResult] = useState<string | null>(null);
  const { lastEvent } = useLive();

  const load = useCallback(() => {
    getSessions().then(setRows).catch(() => setRows([]));
  }, []);

  useEffect(load, [load]);
  useEffect(() => {
    if (lastEvent?.type === "session.revoked") load();
  }, [lastEvent, load]);

  async function confirm() {
    if (!selected) return;
    await revokeSession(selected.id, reason);
    setResult(
      `${selected.username}'s session was terminated. Their next request is refused, and any open connection they hold was closed immediately.`,
    );
    setSelected(null);
    load();
  }

  return (
    <Page
      title="Session revocation"
      description="Terminate any active session. The next request is refused because every route re-reads the session, and the open WebSocket closes without waiting for one."
    >
      {result && (
        <div className="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
          {result}
        </div>
      )}

      {selected && (
        <Card title={`Revoke ${selected.username}'s session?`}>
          <div className="text-sm text-slate-700">
            {selected.full_name} · {selected.role} · {selected.city},{" "}
            {selected.country} · {selected.device_label}
          </div>
          <label className="mt-3 block text-sm font-medium text-slate-700">
            Reason — written to the audit chain
          </label>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="mt-1 w-full max-w-lg rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
          />
          <div className="mt-3 flex gap-2">
            <button
              onClick={confirm}
              disabled={reason.trim().length < 3}
              className="rounded-lg bg-risk-critical px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              Terminate session
            </button>
            <button
              onClick={() => setSelected(null)}
              className="rounded-lg border border-slate-300 px-4 py-2 text-sm"
            >
              Cancel
            </button>
          </div>
        </Card>
      )}

      <div className={selected ? "mt-4" : ""}>
        <Card title={`Active sessions (${rows.length})`}>
          {rows.length === 0 ? (
            <Empty>No active sessions.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">User</th>
                    <th className="px-3 py-2 font-medium">Trust</th>
                    <th className="px-3 py-2 font-medium">Where</th>
                    <th className="px-3 py-2 font-medium">Device</th>
                    <th className="px-3 py-2 font-medium">Started</th>
                    <th className="px-3 py-2" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {rows.map((row) => (
                    <tr key={row.id}>
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
                      <td className="px-3 py-2.5 text-slate-700">
                        {row.city || "—"}, {row.country}
                      </td>
                      <td className="px-3 py-2.5 text-slate-700">
                        {row.device_label ?? "—"}
                      </td>
                      <td className="px-3 py-2.5 text-xs text-slate-600">
                        {new Date(row.started_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <button
                          onClick={() => setSelected(row)}
                          className="rounded border border-red-200 px-2.5 py-1 text-xs text-risk-critical hover:bg-red-50"
                        >
                          Revoke…
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </Page>
  );
}
