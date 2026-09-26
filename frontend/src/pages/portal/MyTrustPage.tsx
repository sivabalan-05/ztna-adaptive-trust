import { useEffect, useState } from "react";
import {
  evaluateMyTrust, getMyTrust, getTrustConfig,
  type TrustAssessment, type TrustConfig,
} from "../../api/client";
import Page, { Card, Empty } from "../../components/layout/Page";

/**
 * Why this account's score is what it is, and what would change it.
 *
 * The weights and bands are read from the server rather than restated here,
 * so the explanation cannot drift from the engine that produced the score.
 */
export default function MyTrustPage() {
  const [config, setConfig] = useState<TrustConfig | null>(null);
  const [assessment, setAssessment] = useState<TrustAssessment | null>(null);
  const [busy, setBusy] = useState(false);

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
      .catch(() => setAssessment(null));
  }, []);

  async function recheck() {
    setBusy(true);
    try {
      setAssessment(await evaluateMyTrust());
    } finally {
      setBusy(false);
    }
  }

  const band = config?.bands.find(
    (b) => assessment && assessment.score >= b.min && assessment.score <= b.max,
  );
  const nextBand = config?.bands
    .filter((b) => assessment && b.min > assessment.score)
    .sort((a, b) => a.min - b.min)[0];

  return (
    <Page
      eyebrow="Your workspace"
      title="Trust & policy"
      description="How your score is calculated, what it currently is, and what would move it."
      actions={
        <button
          onClick={recheck}
          disabled={busy}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm disabled:opacity-50"
        >
          {busy ? "Re-checking…" : "Re-check now"}
        </button>
      }
    >
      <Card title="Your score right now">
        {assessment === null ? (
          <Empty>No score available yet.</Empty>
        ) : (
          <>
            <div className="flex flex-wrap items-baseline gap-3">
              <span className="font-mono text-3xl font-semibold text-slate-900">
                {assessment.score.toFixed(1)}
              </span>
              <span className="text-sm font-medium text-slate-700">
                {assessment.risk_level}
              </span>
              <span className="text-sm text-slate-500">{assessment.headline}</span>
            </div>
            {band && <p className="mt-2 text-sm text-slate-600">{band.description}</p>}
            {nextBand && (
              <p className="mt-1 text-sm text-slate-600">
                Reaching <span className="font-medium">{nextBand.level}</span> needs{" "}
                {(nextBand.min - assessment.score).toFixed(1)} more points — most
                often earned by having this device approved and signing in from a
                familiar network at a usual hour.
              </p>
            )}
          </>
        )}
      </Card>

      <div className="mt-4">
        <Card title="What each factor is worth">
          {config === null ? (
            <Empty>Configuration unavailable.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {Object.entries(config.weights).map(([factor, weight]) => {
                const scored = assessment?.factors.find((f) => f.factor === factor);
                return (
                  <li
                    key={factor}
                    className="flex items-baseline justify-between gap-4 py-2"
                  >
                    <span className="capitalize text-slate-900">{factor}</span>
                    <span className="text-xs text-slate-500">
                      worth {weight} points
                      {scored && scored.points_deducted > 0.05 && (
                        <span className="ml-2 text-risk-critical">
                          −{scored.points_deducted.toFixed(1)} now: {scored.reason}
                        </span>
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Card title="What each band allows">
          {config === null ? (
            <Empty>Configuration unavailable.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {config.bands.map((b) => (
                <li
                  key={b.level}
                  className="flex items-baseline justify-between gap-4 py-2"
                >
                  <span className="font-medium text-slate-900">{b.level}</span>
                  <span className="text-xs text-slate-600">
                    {b.min}–{b.max} · {b.description}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Card title="Trust required per sensitivity">
          {config === null ? (
            <Empty>Configuration unavailable.</Empty>
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {Object.entries(config.sensitivity_floors).map(([tier, floor]) => (
                <li
                  key={tier}
                  className="flex items-baseline justify-between gap-4 py-2"
                >
                  <span className="text-slate-900">{tier}</span>
                  <span className="font-mono text-xs text-slate-600">
                    needs {floor}
                    {assessment && assessment.score < floor && " — out of reach now"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </Page>
  );
}
