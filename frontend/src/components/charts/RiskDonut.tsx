import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { RISK_ORDER, riskColor } from "./palette";

interface Slice {
  level: string;
  count: number;
}

/**
 * Risk distribution across live sessions.
 *
 * A donut is defensible here only because there are exactly four ordered parts
 * of one whole and the total is the headline. Every segment is directly
 * labelled with its band name and count, so the colour is reinforcement rather
 * than the encoding — which matters because the four status hues are not
 * separable by hue alone.
 */
export default function RiskDonut({
  data,
  total,
}: {
  data: Slice[];
  total: number;
}) {
  const ordered = RISK_ORDER.map(
    (level) => data.find((d) => d.level === level) ?? { level, count: 0 },
  );
  const present = ordered.filter((d) => d.count > 0);

  if (total === 0) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-slate-500">
        No live sessions.
      </div>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-6">
      <div className="relative h-48 w-48 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={present}
              dataKey="count"
              nameKey="level"
              innerRadius="62%"
              outerRadius="100%"
              startAngle={90}
              endAngle={-270}
              paddingAngle={2}
              stroke="#fcfcfb"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {present.map((slice) => (
                <Cell key={slice.level} fill={riskColor(slice.level)} />
              ))}
            </Pie>
            <Tooltip
              formatter={(value: number, name: string) => [
                `${value} session${value === 1 ? "" : "s"}`,
                name,
              ]}
              contentStyle={{
                borderRadius: 8,
                border: "1px solid #e7e5e4",
                fontSize: 12,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-semibold text-slate-900">{total}</div>
          <div className="text-xs text-slate-500">sessions</div>
        </div>
      </div>

      {/* Legend doubles as the direct labels: identity is never colour-alone. */}
      <ul className="min-w-40 space-y-2 text-sm">
        {ordered.map((slice) => (
          <li key={slice.level} className="flex items-center gap-2">
            <span
              className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm"
              style={{ backgroundColor: riskColor(slice.level) }}
              aria-hidden
            />
            <span className="text-slate-700">{slice.level}</span>
            <span className="ml-auto font-mono text-slate-900">
              {slice.count}
            </span>
            <span className="w-10 text-right text-xs text-slate-500">
              {total ? Math.round((slice.count / total) * 100) : 0}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
