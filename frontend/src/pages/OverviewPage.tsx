import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getOverview, verifyNow, type Overview } from "../api/client";
import RiskDonut from "../components/charts/RiskDonut";
import StatTile from "../components/charts/StatTile";
import TrustTrend from "../components/charts/TrustTrend";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";
import { SEVERITY_CHIP } from "../components/charts/palette";
import { useLive } from "../live/LiveContext";

export default function OverviewPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [hours, setHours] = useState(24);
  const [busy, setBusy] = useState(false);
  const { lastEvent } = useLive();

  const load = useCallback(() => {
    getOverview(hours).then(setData).catch(() => undefined);
  }, [hours]);

  useEffect(load, [load]);

  // A pushed score means the numbers on this page are already stale.
  useEffect(() => {
    if (lastEvent?.type === "session.score" || lastEvent?.type === "session.revoked") {
      load();
    }
  }, [lastEvent, load]);

  async function runSweep() {
    setBusy(true);
    try {
      await verifyNow();
      load();
    } finally {
      setBusy(false);
    }
  }

  if (!data) {
    return (
      <Page title="Overview">
        <Empty>Loading…</Empty>
      </Page>
    );
  }

  return (
    <Page
      title="Overview"
      description={`Every active session is re-scored every ${data.verification_interval_seconds} seconds.`}
      actions={
        <>
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"
            aria-label="Time range"
          >
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
          </select>
          <button
            onClick={runSweep}
            disabled={busy}
            className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-50 disabled:opacity-50"
          >
            {busy ? "Sweeping…" : "Run sweep now"}
          </button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatTile label="Active sessions" value={data.active_sessions} />
        <StatTile
          label="Mean trust"
          value={data.average_trust_score?.toFixed(1) ?? "—"}
          hint="across live sessions"
        />
        <StatTile
          label="Alerts today"
          value={data.alerts_today}
          hint={`${data.open_alerts} still open`}
          tone={data.open_alerts > 0 ? "warn" : "neutral"}
        />
        <StatTile
          label="Blocked today"
          value={data.blocked_attempts_today}
          hint="denied access attempts"
          tone={data.blocked_attempts_today > 0 ? "bad" : "neutral"}
        />
        <StatTile
          label="Pending devices"
          value={data.pending_devices}
          hint={`${data.total_users} users, ${data.locked_users} locked`}
          tone={data.pending_devices > 0 ? "warn" : "neutral"}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title="Mean trust score over time">
            <TrustTrend data={data.trust_over_time} />
            <p className="mt-2 text-xs text-slate-500">
              Bands shaded behind the line: CRITICAL under 40, HIGH 40–59,
              MEDIUM 60–79, LOW 80 and above.
            </p>
          </Card>
        </div>
        <Card title="Live sessions by risk band">
          <RiskDonut
            data={data.risk_distribution}
            total={data.active_sessions}
          />
        </Card>
      </div>

      <div className="mt-4">
        <Card
          title="Recent alerts"
          actions={
            <Link to="/alerts" className="text-xs text-slate-600 hover:text-slate-900">
              View all →
            </Link>
          }
        >
          {data.recent_alerts.length === 0 ? (
            <Empty>No alerts recorded.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.recent_alerts.map((alert) => (
                <li key={alert.id} className="flex items-start gap-3 py-2.5">
                  <span
                    className={`mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${
                      SEVERITY_CHIP[alert.severity]
                    }`}
                  >
                    {alert.severity}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-slate-900">
                      {alert.title}
                    </div>
                    <div className="text-xs text-slate-500">
                      {alert.username ?? "system"} ·{" "}
                      {new Date(alert.created_at).toLocaleString()}
                    </div>
                  </div>
                  {alert.trust_score !== null && (
                    <RiskChip
                      level={
                        alert.trust_score >= 80
                          ? "LOW"
                          : alert.trust_score >= 60
                            ? "MEDIUM"
                            : alert.trust_score >= 40
                              ? "HIGH"
                              : "CRITICAL"
                      }
                      score={alert.trust_score}
                    />
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <p className="mt-4 text-xs text-slate-500">
        {data.audit_records.toLocaleString()} hash-chained audit records ·
        anomaly model {data.anomaly_model_version ?? "not trained"}
      </p>
    </Page>
  );
}
