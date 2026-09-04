import { useEffect, useState } from "react";
import {
  getUserTrustHistory, getUsers, type TrustHistoryPoint, type UserRow,
} from "../api/client";
import TrustTrend from "../components/charts/TrustTrend";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";

/**
 * A user's trust score over time, with the events that moved it.
 *
 * The annotations are the point: a line alone says the score fell, the table
 * beside it says why and what the engine did about it.
 */
export default function RiskScoresPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [history, setHistory] = useState<TrustHistoryPoint[]>([]);

  useEffect(() => {
    getUsers()
      .then((rows) => {
        setUsers(rows);
        if (rows.length && !selected) setSelected(rows[0].id);
      })
      .catch(() => setUsers([]));
  }, [selected]);

  useEffect(() => {
    if (!selected) return;
    getUserTrustHistory(selected).then(setHistory).catch(() => setHistory([]));
  }, [selected]);

  const notable = history.filter(
    (p) => p.risk_level !== "LOW" || p.trigger === "LOGIN",
  );

  return (
    <Page
      title="Risk scores"
      description="One account's trust score across every session, annotated with what moved it."
      actions={
        <select
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
          aria-label="User"
        >
          {users.map((user) => (
            <option key={user.id} value={user.id}>
              {user.username} ({user.role})
            </option>
          ))}
        </select>
      }
    >
      <Card title="Trust score over time">
        <TrustTrend data={history} height={280} label="Trust score" />
      </Card>

      <div className="mt-4">
        <Card title={`Recalculations (${history.length})`}>
          {notable.length === 0 ? (
            <Empty>No scores recorded for this account.</Empty>
          ) : (
            <div className="max-h-96 overflow-y-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="sticky top-0 bg-white text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">When</th>
                    <th className="px-3 py-2 font-medium">Score</th>
                    <th className="px-3 py-2 font-medium">Trigger</th>
                    <th className="px-3 py-2 font-medium">Action</th>
                    <th className="px-3 py-2 font-medium">Why</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {[...notable].reverse().map((point, index) => (
                    <tr key={`${point.at}-${index}`}>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600">
                        {new Date(point.at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2">
                        <RiskChip level={point.risk_level} score={point.score} />
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {point.trigger}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-600">
                        {point.action.replace(/_/g, " ").toLowerCase()}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-700">
                        {point.reason}
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
