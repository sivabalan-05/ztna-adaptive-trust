import { useEffect, useState } from "react";
import {
  evaluateMyTrust, getMyTrust, getTrustConfig,
  type TrustAssessment, type TrustConfig, type TrustFactor,
} from "../api/client";
import { useLive } from "../live/LiveContext";

const RISK_STYLES: Record<string, { chip: string; bar: string }> = {
  LOW: { chip: "bg-emerald-50 text-emerald-700 ring-emerald-600/20", bar: "bg-risk-low" },
  MEDIUM: { chip: "bg-amber-50 text-amber-700 ring-amber-600/20", bar: "bg-risk-medium" },
  HIGH: { chip: "bg-orange-50 text-orange-700 ring-orange-600/20", bar: "bg-risk-high" },
  CRITICAL: { chip: "bg-red-50 text-red-700 ring-red-600/20", bar: "bg-risk-critical" },
};

/**
 * Renders one factor as a bar showing points lost against points available.
 * The bar length is the weight, the filled part is what this factor cost —
 * so a viewer can see at a glance both how much a factor mattered and how
 * much of its budget it used.
 */
function FactorRow({ factor }: { factor: TrustFactor }) {
  const used = factor.weight > 0 ? (factor.points_deducted / factor.weight) * 100 : 0;
  const spent = factor.points_deducted > 0.05;

  return (
    <div className="py-3">
      <div className="flex items-baseline justify-between gap-4">
        <span className="text-sm font-medium capitalize text-slate-900">
          {factor.factor}
          <span className="ml-2 text-xs font-normal text-slate-400">
            weight {factor.weight}
          </span>
        </span>
        <span
          className={`font-mono text-sm ${spent ? "text-risk-critical" : "text-slate-400"}`}
        >
          {spent ? `−${factor.points_deducted.toFixed(1)}` : "0.0"}
        </span>
      </div>
      <div
        className="mt-1.5 h-1.5 rounded-full bg-slate-100"
        style={{ width: `${factor.weight}%`, minWidth: "60px" }}
        role="img"
        aria-label={`${factor.factor}: ${factor.points_deducted.toFixed(1)} of ${factor.weight} points deducted`}
      >
        <div
          className={`h-full rounded-full ${spent ? "bg-risk-critical" : "bg-slate-200"}`}
          style={{ width: `${Math.min(100, used)}%` }}
        />
      </div>
      <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{factor.reason}</p>
    </div>
  );
}

export default function TrustPanel() {
  const [assessment, setAssessment] = useState<TrustAssessment | null>(null);
  const [config, setConfig] = useState<TrustConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pushed, setPushed] = useState<{ score: number; risk: string; at: string } | null>(
    null,
  );
  const { status, lastEvent, lastHeartbeat } = useLive();

  // A score pushed by the verification sweep, with nobody having asked for it.
  useEffect(() => {
    if (lastEvent?.type !== "session.score") return;
    const p = lastEvent.payload as Record<string, unknown>;
    setPushed({
      score: Number(p.score),
      risk: String(p.risk_level),
      at: lastEvent.at,
    });
    getMyTrust()
      .then((row) =>
        setAssessment((current) =>
          current
            ? {
                ...current,
                score: row.score,
                risk_level: row.risk_level,
                action: row.action,
                anomaly_score: row.anomaly_score,
                headline: row.reason,
                narrative: row.reason,
                total_deducted: 100 - row.score,
                factors: row.factors,
              }
            : current,
        ),
      )
      .catch(() => undefined);
  }, [lastEvent]);

  useEffect(() => {
    getTrustConfig().then(setConfig).catch(() => setConfig(null));
    getMyTrust()
      .then((row) =>
        setAssessment({
          score: row.score,
          weighted_score: row.score,
          risk_level: row.risk_level,
          action: row.action,
          anomaly_score: row.anomaly_score,
          headline: row.reason,
          narrative: row.reason,
          total_deducted: 100 - row.score,
          was_overridden: row.factors.some((f) => f.factor === "override"),
          applied_overrides: [],
          factors: row.factors,
          weights: {},
        }),
      )
      .catch(() => setError("This session has not been scored yet."));
  }, []);

  async function reEvaluate() {
    setBusy(true);
    setError(null);
    try {
      setAssessment(await evaluateMyTrust());
    } catch {
      setError("Re-evaluation failed. The session may have been revoked.");
    } finally {
      setBusy(false);
    }
  }

  if (error && !assessment) {
    return <div className="text-sm text-slate-500">{error}</div>;
  }
  if (!assessment) {
    return <div className="text-sm text-slate-500">Loading trust score…</div>;
  }

  const style = RISK_STYLES[assessment.risk_level] ?? RISK_STYLES.LOW;
  const scored = assessment.factors.filter((f) => f.factor !== "override");
  const override = assessment.factors.find((f) => f.factor === "override");

  return (
    <section className="max-w-4xl">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Trust score</h2>
          <p className="mt-1 max-w-xl text-sm text-slate-600">
            {assessment.narrative}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span
            className="flex items-center gap-1.5 text-xs text-slate-500"
            title={
              status === "open"
                ? `Live. Last heartbeat ${lastHeartbeat?.toLocaleTimeString() ?? "-"}`
                : `Live stream ${status}`
            }
          >
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                status === "open"
                  ? "bg-risk-low"
                  : status === "connecting"
                    ? "bg-risk-medium"
                    : "bg-risk-critical"
              }`}
            />
            {status === "open" ? "live" : status}
          </span>
          <div
            className={`rounded-full px-4 py-2 text-sm font-medium ring-1 ring-inset ${style.chip}`}
          >
            {assessment.score.toFixed(0)} · {assessment.risk_level} ·{" "}
            {assessment.action.replace(/_/g, " ").toLowerCase()}
          </div>
          <button
            onClick={reEvaluate}
            disabled={busy}
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {busy ? "Scoring…" : "Re-verify now"}
          </button>
        </div>
      </div>

      {pushed && (
        <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 px-4 py-2.5 text-xs text-slate-700">
          Pushed by the verification sweep at{" "}
          {new Date(pushed.at).toLocaleTimeString()}: score{" "}
          <strong>{pushed.score.toFixed(0)}</strong> ({pushed.risk}) — no request
          was made from this browser.
        </div>
      )}

      {override && (
        <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
          <div className="font-medium">Hard override applied</div>
          <p className="mt-1">{override.reason}</p>
          <p className="mt-2 text-xs text-red-700">
            The weighted factors alone gave{" "}
            {String(override.signals.weighted_score ?? "—")}; this condition
            clamps the score to {String(override.signals.clamped_to ?? "—")}{" "}
            because it is evidence rather than graded risk.
          </p>
        </div>
      )}

      <div className="mt-5 divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white px-5">
        {scored.map((factor) => (
          <FactorRow key={factor.factor} factor={factor} />
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-500">
        <span>
          Started at 100, deducted {assessment.total_deducted.toFixed(1)}.
        </span>
        {assessment.anomaly_score === null && (
          <span>
            Isolation Forest not yet trained — the behaviour factor uses profile
            deviation only.
          </span>
        )}
        {config && (
          <span>
            Re-verified automatically every{" "}
            {config.continuous_verification_interval_seconds} seconds.
          </span>
        )}
      </div>
    </section>
  );
}
