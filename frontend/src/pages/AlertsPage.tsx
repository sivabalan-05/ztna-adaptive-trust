import { useCallback, useEffect, useState } from "react";
import {
  acknowledgeAlert, getAlerts, resolveAlert, type AlertRow,
} from "../api/client";
import Page, { Card, Empty } from "../components/layout/Page";
import { SEVERITY_CHIP } from "../components/charts/palette";
import { useLive } from "../live/LiveContext";

const STATUS_TABS = ["OPEN", "ACKNOWLEDGED", "RESOLVED", ""] as const;

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [tab, setTab] = useState<string>("OPEN");
  const [severity, setSeverity] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const { lastEvent } = useLive();

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (tab) params.set("status", tab);
    if (severity) params.set("severity", severity);
    params.set("limit", "100");
    getAlerts(`?${params}`)
      .then((d) => {
        setAlerts(d.alerts);
        setTotal(d.total);
      })
      .catch(() => setAlerts([]));
  }, [tab, severity]);

  useEffect(load, [load]);

  useEffect(() => {
    if (lastEvent?.type === "session.score" || lastEvent?.type === "session.revoked") {
      load();
    }
  }, [lastEvent, load]);

  async function onAcknowledge(alert: AlertRow) {
    await acknowledgeAlert(alert.id);
    load();
  }

  async function onResolve(alert: AlertRow) {
    const note = window.prompt(
      "Resolution note — what did you find?",
      "Investigated and contained.",
    );
    if (note === null) return;
    await resolveAlert(alert.id, note);
    load();
  }

  return (
    <Page
      title="Alerts"
      description="Raised by the trust engine and the policy enforcement point. Acknowledging and resolving are both written to the audit chain."
      actions={
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
          aria-label="Severity"
        >
          <option value="">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      }
    >
      <div className="mb-4 flex gap-1">
        {STATUS_TABS.map((s) => (
          <button
            key={s || "all"}
            onClick={() => setTab(s)}
            className={`rounded-lg px-3 py-1.5 text-sm ${
              tab === s
                ? "bg-shell text-white"
                : "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
            }`}
          >
            {s || "All"}
          </button>
        ))}
        <span className="ml-auto self-center text-xs text-slate-500">
          {total} alert{total === 1 ? "" : "s"}
        </span>
      </div>

      <Card>
        {alerts.length === 0 ? (
          <Empty>Nothing here. That is the good outcome.</Empty>
        ) : (
          <ul className="divide-y divide-slate-100">
            {alerts.map((alert) => (
              <li key={alert.id} className="py-3">
                <div className="flex items-start gap-3">
                  <span
                    className={`mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${
                      SEVERITY_CHIP[alert.severity]
                    }`}
                  >
                    {alert.severity}
                  </span>
                  <div className="min-w-0 flex-1">
                    <button
                      onClick={() =>
                        setExpanded(expanded === alert.id ? null : alert.id)
                      }
                      className="text-left text-sm font-medium text-slate-900 hover:underline"
                    >
                      {alert.title}
                    </button>
                    <div className="mt-0.5 text-xs text-slate-500">
                      {alert.category} · {alert.username ?? "system"} ·{" "}
                      {new Date(alert.created_at).toLocaleString()}
                      {alert.trust_score !== null &&
                        ` · trust ${alert.trust_score.toFixed(0)}`}
                    </div>
                    {expanded === alert.id && (
                      <div className="mt-2 space-y-2">
                        <p className="text-sm text-slate-700">
                          {alert.description}
                        </p>
                        <pre className="overflow-x-auto rounded bg-slate-50 p-3 text-[11px] leading-relaxed text-slate-700">
                          {JSON.stringify(alert.evidence, null, 2)}
                        </pre>
                        {alert.resolution_note && (
                          <p className="text-xs text-slate-600">
                            Resolved by {alert.resolved_by}:{" "}
                            {alert.resolution_note}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="text-xs text-slate-500">
                      {alert.status}
                    </span>
                    {alert.status === "OPEN" && (
                      <button
                        onClick={() => onAcknowledge(alert)}
                        className="rounded border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50"
                      >
                        Acknowledge
                      </button>
                    )}
                    {alert.status !== "RESOLVED" && (
                      <button
                        onClick={() => onResolve(alert)}
                        className="rounded border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50"
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </Page>
  );
}
