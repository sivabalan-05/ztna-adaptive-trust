import {
  CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import { GRID, INK_MUTED, TREND_COLOR } from "./palette";

interface Point {
  at: string;
  score: number;
  risk_level?: string;
}

/**
 * Mean trust score over time.
 *
 * One series, so no legend — the title names it. The risk bands are drawn as
 * recessive background regions rather than as extra series, because they are
 * the scale's meaning, not data.
 */
export default function TrustTrend({
  data,
  height = 240,
  label = "Mean trust score",
}: {
  data: Point[];
  height?: number;
  label?: string;
}) {
  if (data.length === 0) {
    return (
      <div
        className="flex items-center justify-center text-sm text-slate-500"
        style={{ height }}
      >
        No scores recorded in this window.
      </div>
    );
  }

  const points = data.map((p) => ({
    ...p,
    t: new Date(p.at).getTime(),
  }));

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={points} margin={{ top: 8, right: 12, bottom: 4, left: -8 }}>
        {/* Band regions: the scale's meaning, drawn recessively behind the data. */}
        <ReferenceArea y1={0} y2={40} fill="#d03b3b" fillOpacity={0.05} />
        <ReferenceArea y1={40} y2={60} fill="#ec835a" fillOpacity={0.05} />
        <ReferenceArea y1={60} y2={80} fill="#fab219" fillOpacity={0.05} />
        <ReferenceArea y1={80} y2={100} fill="#0ca30c" fillOpacity={0.05} />

        <CartesianGrid stroke={GRID} strokeDasharray="2 4" vertical={false} />
        <XAxis
          dataKey="t"
          type="number"
          domain={["dataMin", "dataMax"]}
          scale="time"
          tickFormatter={(t) =>
            new Date(t).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })
          }
          tick={{ fontSize: 11, fill: INK_MUTED }}
          stroke={GRID}
          minTickGap={40}
        />
        <YAxis
          domain={[0, 100]}
          ticks={[0, 40, 60, 80, 100]}
          tick={{ fontSize: 11, fill: INK_MUTED }}
          stroke={GRID}
          width={40}
        />
        <Tooltip
          labelFormatter={(t) => new Date(Number(t)).toLocaleString()}
          formatter={(value: number) => [value.toFixed(1), label]}
          contentStyle={{
            borderRadius: 8,
            border: "1px solid #e7e5e4",
            fontSize: 12,
          }}
          cursor={{ stroke: INK_MUTED, strokeDasharray: "3 3" }}
        />
        <Line
          type="monotone"
          dataKey="score"
          stroke={TREND_COLOR}
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: "#fcfcfb" }}
          isAnimationActive={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
