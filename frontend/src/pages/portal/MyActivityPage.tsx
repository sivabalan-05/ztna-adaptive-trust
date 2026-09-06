import { useEffect, useState } from "react";
import {
  getAccessHistory, getMySessions,
  type AccessHistoryRow, type LiveSession,
} from "../../api/client";
import Page, { Card, Empty, RiskChip } from "../../components/layout/Page";

/**
 * This account's own record: what it asked for, what was decided, and where
 * it is signed in. The same evidence an analyst sees, scoped to one user.
 */
export default function MyActivityPage() {
  const [history, setHistory] = useState<AccessHistoryRow[]>([]);
  const [sessions, setSessions] = useState<LiveSession[]>([]);

  useEffect(() => {
    getAccessHistory(100).then(setHistory).catch(() => setHistory([]));
    getMySessions().then(setSessions).catch(() => setSessions([]));
  }, []);

  const denied = history.filter((row) => !row.granted).length;

  return (
    <Page
      title="My activity"
      description="Every access decision made about this account, and every session it currently holds."
    >
      <Card title={`Access decisions (${history.length}, ${denied} refused)`}>
        {history.length === 0 ? (
          <Empty>No access attempts recorded yet.</Empty>
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="sticky top-0 bg-white text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">When</th>
                  <th className="px-3 py-2 font-medium">Resource</th>
                  <th className="px-3 py-2 font-medium">Score</th>
                  <th className="px-3 py-2 font-medium">Outcome</th>
                  <th className="px-3 py-2 font-medium">Why</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {history.map((row) => (
                  <tr key={row.id}>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600">
                      {new Date(row.requested_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-slate-900">{row.resource ?? "—"}</td>
                    <td className="px-3 py-2">
                      <RiskChip level={row.risk_level} score={row.score_at_request} />
                    </td>
                    <td
                      className={`px-3 py-2 text-xs font-medium ${
                        row.granted ? "text-emerald-700" : "text-risk-critical"
                      }`}
                    >
                      {row.granted ? "allowed" : "denied"}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-700">{row.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="mt-4">
        <Card title={`My sessions (${sessions.length})`}>
          {sessions.length === 0 ? (
            <Empty>No sessions found.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">Started</th>
                    <th className="px-3 py-2 font-medium">Device</th>
                    <th className="px-3 py-2 font-medium">Where</th>
                    <th className="px-3 py-2 font-medium">Score</th>
                    <th className="px-3 py-2 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {sessions.map((session) => (
                    <tr key={session.id}>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600">
                        {new Date(session.started_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-700">
                        {session.device_label ?? "—"}
                        {session.device_status && (
                          <span className="ml-1 text-slate-400">
                            ({session.device_status})
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {session.ip_address}
                        {session.city && ` · ${session.city}`}
                      </td>
                      <td className="px-3 py-2">
                        <RiskChip
                          level={session.current_risk_level}
                          score={session.current_trust_score}
                        />
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {session.status}
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
