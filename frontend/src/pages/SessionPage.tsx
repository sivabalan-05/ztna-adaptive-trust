import { useAuth } from "../auth/AuthContext";
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
  const { me, refreshMe } = useAuth();

  if (!me) return null;
  const { session } = me;

  return (
    <div className="p-8">
      <div className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
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

      <button
        onClick={refreshMe}
        className="mt-6 rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
      >
        Re-verify this session
      </button>
    </div>
  );
}
