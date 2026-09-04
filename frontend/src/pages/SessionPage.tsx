import { useEffect, useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { getMyDevices, type DeviceInfo } from "../api/client";
import TrustPanel from "../components/TrustPanel";

const RISK_STYLES: Record<string, string> = {
  LOW: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  MEDIUM: "bg-amber-50 text-amber-700 ring-amber-600/20",
  HIGH: "bg-orange-50 text-orange-700 ring-orange-600/20",
  CRITICAL: "bg-red-50 text-red-700 ring-red-600/20",
};

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-white px-4 py-3">
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm font-medium text-slate-900">{value}</dd>
    </div>
  );
}

export default function SessionPage() {
  const { me, signOut, refreshMe } = useAuth();
  const [devices, setDevices] = useState<DeviceInfo[]>([]);

  useEffect(() => {
    getMyDevices().then(setDevices).catch(() => setDevices([]));
  }, [me?.id]);

  if (!me) return null;
  const { session } = me;

  return (
    <div className="flex min-h-full">
      <aside className="w-64 shrink-0 bg-shell p-6 text-slate-300">
        <div className="text-lg font-semibold text-white">ZTNA</div>
        <div className="mt-1 text-xs text-slate-400">Adaptive Trust Scoring</div>

        <div className="mt-8 rounded-lg bg-shell-soft p-3">
          <div className="text-sm font-medium text-white">{me.full_name}</div>
          <div className="text-xs text-slate-400">
            {me.username} · {me.role}
          </div>
        </div>

        <nav className="mt-6 space-y-1 text-sm">
          <div className="rounded bg-shell-soft px-3 py-2 text-white">
            Session
          </div>
          {[
            "Overview", "Users & Devices", "Live Monitoring", "Risk Scores",
            "Alerts", "Trust Score", "Audit Logs", "Session Revocation",
          ].map((label) => (
            <div
              key={label}
              className="rounded px-3 py-2 text-slate-500"
              title="Available in Phase 9"
            >
              {label}
            </div>
          ))}
        </nav>

        <button
          onClick={signOut}
          className="mt-8 w-full rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-300 hover:bg-shell-soft"
        >
          Sign out
        </button>
      </aside>

      <main className="flex-1 overflow-auto p-10">
        <div className="flex items-start justify-between gap-6">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">
              Authenticated session
            </h1>
            <p className="mt-1 text-sm text-slate-600">
              Password and TOTP both verified. This session is re-checked on
              every request.
            </p>
          </div>
          <div
            className={`rounded-full px-4 py-2 text-sm font-medium ring-1 ring-inset ${
              RISK_STYLES[session.current_risk_level] ?? RISK_STYLES.LOW
            }`}
          >
            Session {session.current_risk_level}
          </div>
        </div>

        <div className="mt-8">
          <TrustPanel />
        </div>

        <h2 className="mt-8 text-sm font-semibold text-slate-900">Session</h2>
        <dl className="mt-3 grid max-w-4xl grid-cols-2 gap-px overflow-hidden rounded-lg border border-slate-200 bg-slate-200 sm:grid-cols-3">
          <Field label="Status" value={session.status} />
          <Field label="MFA" value={session.mfa_passed ? "verified" : "pending"} />
          <Field label="Action" value={session.current_action} />
          <Field label="IP address" value={session.ip_address || "—"} />
          <Field label="Requests" value={String(session.request_count)} />
          <Field
            label="Started"
            value={new Date(session.started_at).toLocaleString()}
          />
          <Field
            label="Expires"
            value={new Date(session.expires_at).toLocaleString()}
          />
          <Field label="Role" value={me.role} />
          <Field label="Department" value={me.department || "—"} />
        </dl>

        <h2 className="mt-8 text-sm font-semibold text-slate-900">
          Registered devices
        </h2>
        <div className="mt-3 max-w-4xl overflow-x-auto rounded-lg border border-slate-200">
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2 font-medium">Device</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Seen</th>
                <th className="px-4 py-2 font-medium">Last used</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 bg-white">
              {devices.map((device) => (
                <tr key={device.id}>
                  <td className="px-4 py-2">
                    <div className="font-medium text-slate-900">{device.label}</div>
                    <div className="font-mono text-[11px] text-slate-400">
                      {device.fingerprint.slice(0, 24)}…
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={
                        device.status === "APPROVED"
                          ? "text-emerald-700"
                          : device.status === "PENDING"
                            ? "text-amber-700"
                            : "text-risk-critical"
                      }
                    >
                      {device.status}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-600">{device.seen_count}×</td>
                  <td className="px-4 py-2 text-slate-600">
                    {new Date(device.last_seen_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {devices.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-slate-500">
                    No devices registered.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <button
          onClick={refreshMe}
          className="mt-6 rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
        >
          Re-verify this session
        </button>
      </main>
    </div>
  );
}
