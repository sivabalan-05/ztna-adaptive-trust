import { useState, type FormEvent } from "react";
import {
  apiErrorMessage, createUser, type CreatedUser, type NewUser, type RoleRow,
} from "../api/client";
import { Card } from "./layout/Page";

const USERNAME_PATTERN = /^[a-z0-9._-]{3,64}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 12;
// No look-alike characters (I, O, l, 0, 1) so a generated password survives being read aloud.
const PASSWORD_ALPHABET =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_";

/** A random 16-character password from the browser's CSPRNG. */
function generatePassword(): string {
  const bytes = new Uint32Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => PASSWORD_ALPHABET[b % PASSWORD_ALPHABET.length]).join("");
}

function blankForm(roles: RoleRow[]): NewUser {
  return {
    username: "",
    email: "",
    full_name: "",
    password: "",
    role: roles.some((r) => r.name === "employee") ? "employee" : (roles[0]?.name ?? ""),
    department: "",
    home_city: "Coimbatore",
  };
}

/** Mirrors the server's rules so obvious mistakes are caught before a round trip. */
function validate(form: NewUser): string | null {
  if (!form.full_name.trim()) return "Enter the user's full name.";
  if (!USERNAME_PATTERN.test(form.username)) {
    return "Username must be 3–64 characters: lowercase letters, digits, dots, underscores or hyphens.";
  }
  if (!EMAIL_PATTERN.test(form.email)) return "Enter a valid email address.";
  if (form.password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (!form.role) return "Choose a role.";
  return null;
}

const INPUT =
  "mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900";
const LABEL = "block text-sm font-medium text-slate-700";

/**
 * Inline "Add user" form for administrators. Like ConfirmAction it renders in
 * the page rather than as an overlay, because native and overlay dialogs are
 * suppressed in some embedded browser contexts.
 *
 * The admin chooses the initial password; the new user enrols their own MFA
 * authenticator the first time they sign in, so no MFA secret is handled here.
 */
export default function AddUserPanel({
  roles,
  onCreated,
  onClose,
}: {
  roles: RoleRow[];
  onCreated: (user: CreatedUser) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<NewUser>(() => blankForm(roles));
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [created, setCreated] = useState<{ user: CreatedUser; password: string } | null>(null);

  const set = (field: keyof NewUser) => (value: string) =>
    setForm((current) => ({ ...current, [field]: value }));

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("Could not copy automatically — select the text and copy it manually.");
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const problem = validate(form);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const user = await createUser({
        ...form,
        full_name: form.full_name.trim(),
        department: form.department.trim(),
        home_city: form.home_city.trim() || "Coimbatore",
      });
      setCreated({ user, password: form.password });
      onCreated(user);
    } catch (e) {
      setError(apiErrorMessage(e, "Could not create the user."));
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    const credentials = `Username: ${created.user.username}\nPassword: ${created.password}`;
    return (
      <Card title="User created">
        <div className="text-sm text-slate-700">
          <span className="font-medium text-slate-900">{created.user.full_name}</span>{" "}
          can now sign in as{" "}
          <span className="font-mono text-slate-900">{created.user.username}</span> with the{" "}
          <span className="font-medium">{created.user.role}</span> role. They will set up their
          authenticator app the first time they sign in.
        </div>
        <div className="mt-3 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800">
          <div>Username: {created.user.username}</div>
          <div>Password: {created.password}</div>
        </div>
        <div className="mt-1 text-xs text-slate-500">
          This password is shown only now — share it securely and ask them to change it.
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => copy(credentials)}
            className="rounded-lg bg-shell px-4 py-2 text-sm font-medium text-white"
          >
            {copied ? "Copied" : "Copy credentials"}
          </button>
          <button
            type="button"
            onClick={() => {
              setCreated(null);
              setForm(blankForm(roles));
              setShowPassword(false);
            }}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm"
          >
            Add another
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm"
          >
            Done
          </button>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Add user">
      <form onSubmit={submit} noValidate>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor="new-user-name" className={LABEL}>Full name</label>
            <input
              id="new-user-name"
              autoFocus
              value={form.full_name}
              onChange={(e) => set("full_name")(e.target.value)}
              placeholder="Priya Raman"
              maxLength={128}
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="new-user-username" className={LABEL}>Username</label>
            <input
              id="new-user-username"
              value={form.username}
              onChange={(e) => set("username")(e.target.value.toLowerCase())}
              placeholder="priya.raman"
              autoComplete="off"
              maxLength={64}
              className={`${INPUT} font-mono`}
            />
          </div>
          <div>
            <label htmlFor="new-user-email" className={LABEL}>Email</label>
            <input
              id="new-user-email"
              type="email"
              value={form.email}
              onChange={(e) => set("email")(e.target.value.trim())}
              placeholder="priya.raman@company.com"
              autoComplete="off"
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="new-user-role" className={LABEL}>Role</label>
            <select
              id="new-user-role"
              value={form.role}
              onChange={(e) => set("role")(e.target.value)}
              className={INPUT}
            >
              {roles.map((role) => (
                <option key={role.name} value={role.name}>{role.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="new-user-department" className={LABEL}>
              Department <span className="font-normal text-slate-400">(optional)</span>
            </label>
            <input
              id="new-user-department"
              value={form.department}
              onChange={(e) => set("department")(e.target.value)}
              placeholder="Finance"
              maxLength={64}
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="new-user-city" className={LABEL}>
              Home city <span className="font-normal text-slate-400">(used for impossible-travel checks)</span>
            </label>
            <input
              id="new-user-city"
              value={form.home_city}
              onChange={(e) => set("home_city")(e.target.value)}
              maxLength={64}
              className={INPUT}
            />
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="new-user-password" className={LABEL}>Initial password</label>
            <div className="mt-1 flex flex-wrap gap-2">
              <input
                id="new-user-password"
                type={showPassword ? "text" : "password"}
                value={form.password}
                onChange={(e) => set("password")(e.target.value)}
                placeholder={`At least ${MIN_PASSWORD_LENGTH} characters`}
                autoComplete="new-password"
                maxLength={256}
                className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-slate-900"
              />
              <button
                type="button"
                onClick={() => {
                  set("password")(generatePassword());
                  setShowPassword(true);
                }}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              >
                Generate
              </button>
              <button
                type="button"
                onClick={() => setShowPassword((shown) => !shown)}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              >
                {showPassword ? "Hide" : "Show"}
              </button>
            </div>
          </div>
        </div>

        {error && (
          <div role="alert" className="mt-3 rounded-lg bg-red-50 px-4 py-2.5 text-sm text-risk-critical">
            {error}
          </div>
        )}

        <div className="mt-4 flex gap-2">
          <button
            type="submit"
            disabled={busy}
            className="rounded-lg bg-shell px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create user"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm"
          >
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}
