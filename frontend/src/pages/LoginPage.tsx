import { useEffect, useRef, useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { collectDeviceSignals } from "../lib/fingerprint";
import SignalScene from "../components/SignalScene";

export default function LoginPage() {
  const {
    challenge, enrolment, error, signIn, submitCode, confirmEnrolment,
    cancelChallenge,
  } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [fingerprint, setFingerprint] = useState("");
  const codeRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    collectDeviceSignals().then((s) => setFingerprint(s.fingerprint));
  }, []);

  useEffect(() => {
    if (challenge) {
      setCode("");
      codeRef.current?.focus();
    }
  }, [challenge]);

  async function onSubmitPassword(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await signIn(username, password);
    } catch {
      /* error is surfaced through the context */
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  async function onSubmitCode(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await submitCode(code);
    } catch {
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  async function onSubmitEnrolmentCode(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await confirmEnrolment(code);
    } catch {
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <section className="login-story" aria-label="Platform overview">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">Z</div>
          <div>
            <div className="brand-name">PENETRATION PROTECTOR</div>
            <div className="brand-caption">Zero trust control plane</div>
          </div>
        </div>
        <div className="login-story-content">
          <div className="login-eyebrow"><span className="stream-dot is-open" />Adaptive access, continuously verified</div>
          <h1 className="login-title">Trust is earned.<br /><em>Every request.</em></h1>
          <p className="login-intro">
            One place to understand who is connected, what they can reach, and
            why each access decision was made.
          </p>
          <div className="login-signals">
            <div className="login-signal"><strong>Identity + MFA</strong><span>Every session begins with proof</span></div>
            <div className="login-signal"><strong>Live trust signals</strong><span>Device, network, place and behavior</span></div>
            <div className="login-signal"><strong>Least privilege</strong><span>Access shaped by role and risk</span></div>
            <div className="login-signal"><strong>Verifiable decisions</strong><span>Every outcome enters the audit trail</span></div>
          </div>
        </div>
        <SignalScene />
        <div className="login-story-footer">PENETRATION PROTECTOR · ZERO TRUST ACCESS</div>
      </section>

      <section className="login-workspace" aria-label="Sign in">
        <div className="login-workspace-inner">
          <div className="login-mobile-brand">
            <div className="brand-mark" aria-hidden="true">Z</div>
            <div>
              <div className="brand-name">PENETRATION PROTECTOR</div>
              <div className="brand-caption">Zero trust control plane</div>
            </div>
          </div>
          <SignalScene compact />
          <div className="mb-5">
            <div className="page-kicker">Secure sign in</div>
            <h2 className="text-2xl font-semibold tracking-tight text-slate-900">
              {challenge ? "Verify your identity" : "Welcome back"}
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-slate-500">
              {challenge ? "Complete the second step to open your secure workspace." : "Sign in to your protected workspace."}
            </p>
          </div>

        <div className="auth-card">
          {!challenge ? (
            <form onSubmit={onSubmitPassword} className="space-y-5">
              <div>
                <label
                  htmlFor="username"
                  className="block text-sm font-medium text-slate-700"
                >
                  Username
                </label>
                <input
                  id="username"
                  autoComplete="username"
                  autoFocus
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  aria-invalid={!!error}
                  aria-describedby={error ? "login-error" : undefined}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
                  required
                />
              </div>
              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-slate-700"
                >
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  aria-invalid={!!error}
                  aria-describedby={error ? "login-error" : undefined}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
                  required
                />
              </div>

              {error && (
                <div id="login-error" role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={busy}
                className="w-full rounded-lg bg-shell px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
              >
                {busy ? "Verifying…" : "Continue"}
              </button>
            </form>
          ) : challenge.enrolment_required ? (
            <form onSubmit={onSubmitEnrolmentCode} className="space-y-5">
              <div>
                <div className="text-sm font-medium text-slate-900">
                  Set up two-factor authentication
                </div>
                <p className="mt-1 text-sm text-slate-500">
                  This account has never signed in before. Scan the QR code
                  with an authenticator app, then enter the 6-digit code it
                  shows to finish setting up and sign in.
                </p>
              </div>

              {enrolment ? (
                <>
                  <div className="flex justify-center rounded-lg border border-slate-200 bg-white p-4">
                    <img
                      src={enrolment.qr_code_svg_data_uri}
                      alt="Scan with your authenticator app"
                      className="h-40 w-40"
                    />
                  </div>
                  <div className="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-500">
                    Can't scan it? Enter this key manually:
                    <div className="mt-1 break-all font-mono text-[11px] text-slate-700">
                      {enrolment.secret}
                    </div>
                  </div>
                </>
              ) : (
                <div className="rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-500">
                  Preparing your QR code…
                </div>
              )}

              <div>
                <label htmlFor="enrol-code" className="block text-sm font-medium text-slate-700">
                  Verification code
                </label>
                <input
                  id="enrol-code"
                  ref={codeRef}
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  aria-invalid={!!error}
                  aria-describedby={error ? "enrol-error" : undefined}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-center font-mono text-lg tracking-[0.4em] outline-none focus:border-slate-900"
                  required
                />
              </div>

              {error && (
                <div id="enrol-error" role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={busy || code.length !== 6 || !enrolment}
                className="w-full rounded-lg bg-shell px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
              >
                {busy ? "Confirming…" : "Confirm and sign in"}
              </button>
              <button
                type="button"
                onClick={cancelChallenge}
                className="w-full text-sm text-slate-500 hover:text-slate-800"
              >
                Start over
              </button>
            </form>
          ) : (
            <form onSubmit={onSubmitCode} className="space-y-5">
              <div>
                <div className="text-sm font-medium text-slate-900">
                  Two-factor verification
                </div>
                <p className="mt-1 text-sm text-slate-500">
                  Your password was accepted but grants no access on its own.
                  Enter the 6-digit code from your authenticator app.
                </p>
              </div>

              <div
                className={`rounded-lg px-3 py-2 text-xs ${
                  challenge.device_known
                    ? "bg-emerald-50 text-emerald-800"
                    : "bg-amber-50 text-amber-800"
                }`}
              >
                {challenge.device_known
                  ? `Recognised device · ${challenge.device_status}`
                  : `New device registered as ${challenge.device_status} — this lowers your trust score until an administrator approves it.`}
              </div>

              <div>
                <label htmlFor="code" className="block text-sm font-medium text-slate-700">
                  Verification code
                </label>
                <input
                  id="code"
                  ref={codeRef}
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  aria-invalid={!!error}
                  aria-describedby={error ? "mfa-error" : undefined}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-center font-mono text-lg tracking-[0.4em] outline-none focus:border-slate-900"
                  required
                />
              </div>

              {error && (
                <div id="mfa-error" role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={busy || code.length !== 6}
                className="w-full rounded-lg bg-shell px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"
              >
                {busy ? "Checking…" : "Verify and sign in"}
              </button>
              <button
                type="button"
                onClick={cancelChallenge}
                className="w-full text-sm text-slate-500 hover:text-slate-800"
              >
                Start over
              </button>
            </form>
          )}
        </div>

        <div className="device-note">
          <div className="font-semibold text-slate-700">Device fingerprint</div>
          <div className="mt-1 break-all font-mono text-[11px]">
            {fingerprint ? `${fingerprint.slice(0, 32)}…` : "computing…"}
          </div>
          <p className="mt-2">
            Computed in the browser from user agent, platform, screen, timezone,
            language and a canvas/WebGL render, then sent as
            <code className="mx-1">X-Device-Fingerprint</code>.
          </p>
        </div>
      </div>
      </section>
    </div>
  );
}
