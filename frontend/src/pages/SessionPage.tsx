import { useAuth } from "../auth/AuthContext";
import TrustPanel from "../components/TrustPanel";
import Page, { Card } from "../components/layout/Page";

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
    <Page
      eyebrow="Your workspace"
      title="Authenticated session"
      description="Password and TOTP both verified. This session is re-checked on every request."
      actions={
        <span className={`rounded-full px-3 py-1.5 text-[10px] font-semibold tracking-wide ring-1 ring-inset ${RISK_STYLES[session.current_risk_level] ?? RISK_STYLES.LOW}`}>
          Session {session.current_risk_level}
        </span>
      }
    >
      <div className="surface-panel mt-5 p-5 sm:p-6">
        <TrustPanel />
      </div>

      <div className="mt-4 max-w-5xl">
        <Card title="Session details">
          <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-slate-200 bg-slate-200 sm:grid-cols-3">
            <Field label="Status" value={session.status} />
            <Field label="MFA" value={session.mfa_passed ? "verified" : "pending"} />
            <Field label="Action" value={session.current_action} />
            <Field label="IP address" value={session.ip_address || "—"} />
            <Field label="Requests" value={String(session.request_count)} />
            <Field label="Started" value={new Date(session.started_at).toLocaleString()} />
            <Field label="Expires" value={new Date(session.expires_at).toLocaleString()} />
            <Field label="Role" value={me.role} />
            <Field label="Department" value={me.department || "—"} />
          </dl>
        </Card>
      </div>

      <button
        onClick={refreshMe}
        className="mt-6 rounded-lg border border-slate-300 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
      >
        Re-verify this session
      </button>
    </Page>
  );
}
