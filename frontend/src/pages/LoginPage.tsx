import { useEffect, useRef, useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { collectDeviceSignals } from "../lib/fingerprint";

export default function LoginPage() {
  const { challenge, error, signIn, submitCode, cancelChallenge } = useAuth();
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

  return (
    <div className="flex min-h-full items-center justify-center bg-slate-50 p-6">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="text-xl font-semibold text-slate-900">
            Zero Trust Network Access
          </div>
          <p className="mt-1 text-sm text-slate-500">
            Never trust, always verify.
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm">
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
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
                  required
                />
              </div>

              {error && (
                <div className="rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
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
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-center font-mono text-lg tracking-[0.4em] outline-none focus:border-slate-900"
                  required
                />
              </div>

              {error && (
                <div className="rounded-lg bg-red-50 px-3 py-2 text-sm text-risk-critical">
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

        <div className="mt-6 rounded-lg border border-slate-200 bg-white p-4 text-xs text-slate-500">
          <div className="font-medium text-slate-700">This device</div>
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
    </div>
  );
}
