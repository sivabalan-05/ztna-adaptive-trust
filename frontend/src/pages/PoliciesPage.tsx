import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  apiErrorMessage, createPolicy, deletePolicy, getPolicies, updatePolicy,
  type PolicyRow,
} from "../api/client";
import { usePermissions } from "../auth/usePermissions";
import Page, { Card, Empty } from "../components/layout/Page";

const SENSITIVITIES = ["", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

const EMPTY_FORM = {
  name: "", description: "", sensitivity: "", min_trust_score: 0,
  effect: "ALLOW", priority: 100, require_mfa: false,
  require_known_device: false, deny_vpn: false,
};

/**
 * The rules the enforcement point evaluates.
 *
 * Highest priority wins and DENY beats ALLOW on a tie, so the list is shown in
 * the order the engine considers it rather than alphabetically.
 */
export default function PoliciesPage() {
  const { can } = usePermissions();
  const writable = can("policies:write");
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);

  const load = useCallback(() => {
    getPolicies().then(setPolicies).catch(() => setPolicies([]));
  }, []);

  useEffect(load, [load]);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createPolicy({
        ...form,
        sensitivity: form.sensitivity || null,
        min_trust_score: Number(form.min_trust_score),
        priority: Number(form.priority),
      });
      setForm(EMPTY_FORM);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not create the policy."));
    } finally {
      setBusy(false);
    }
  }

  async function onToggle(policy: PolicyRow) {
    setError("");
    try {
      await updatePolicy(policy.id, { enabled: !policy.enabled });
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not update the policy."));
    }
  }

  async function onDelete(policy: PolicyRow) {
    setError("");
    try {
      await deletePolicy(policy.id);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not delete the policy."));
    }
  }

  return (
    <Page
      title="Policies"
      description="Evaluated on every access decision, highest priority first. A DENY beats an ALLOW at the same priority."
    >
      {error && (
        <div className="mb-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-risk-critical">
          {error}
        </div>
      )}

      {writable && (
        <div className="mb-4">
          <Card title="Add a policy">
            <form onSubmit={onCreate} className="grid gap-3 sm:grid-cols-2">
              <input
                required
                minLength={3}
                placeholder="Policy name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <input
                placeholder="Description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <select
                value={form.sensitivity}
                onChange={(e) => setForm({ ...form, sensitivity: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Applies to sensitivity"
              >
                {SENSITIVITIES.map((level) => (
                  <option key={level || "any"} value={level}>
                    {level || "Any sensitivity"}
                  </option>
                ))}
              </select>
              <select
                value={form.effect}
                onChange={(e) => setForm({ ...form, effect: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Effect"
              >
                <option value="ALLOW">ALLOW</option>
                <option value="DENY">DENY</option>
              </select>
              <label className="text-sm text-slate-700">
                Minimum trust score
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={form.min_trust_score}
                  onChange={(e) =>
                    setForm({ ...form, min_trust_score: Number(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="text-sm text-slate-700">
                Priority
                <input
                  type="number"
                  min={0}
                  max={1000}
                  value={form.priority}
                  onChange={(e) =>
                    setForm({ ...form, priority: Number(e.target.value) })
                  }
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <div className="flex flex-wrap gap-4 text-sm text-slate-700 sm:col-span-2">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.require_mfa}
                    onChange={(e) =>
                      setForm({ ...form, require_mfa: e.target.checked })
                    }
                  />
                  Require MFA
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.require_known_device}
                    onChange={(e) =>
                      setForm({ ...form, require_known_device: e.target.checked })
                    }
                  />
                  Require a known device
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.deny_vpn}
                    onChange={(e) => setForm({ ...form, deny_vpn: e.target.checked })}
                  />
                  Deny VPN and datacentre traffic
                </label>
              </div>
              <button
                type="submit"
                disabled={busy}
                className="rounded-lg bg-shell px-4 py-2 text-sm font-medium text-white disabled:opacity-50 sm:col-span-2"
              >
                {busy ? "Saving…" : "Add policy"}
              </button>
            </form>
          </Card>
        </div>
      )}

      <Card title={`Policies (${policies.length})`}>
        {policies.length === 0 ? (
          <Empty>No policies defined.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Priority</th>
                  <th className="px-3 py-2 font-medium">Policy</th>
                  <th className="px-3 py-2 font-medium">Applies to</th>
                  <th className="px-3 py-2 font-medium">Conditions</th>
                  <th className="px-3 py-2 font-medium">Effect</th>
                  {writable && <th className="px-3 py-2 font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {policies.map((policy) => (
                  <tr key={policy.id} className={policy.enabled ? "" : "opacity-50"}>
                    <td className="px-3 py-2 font-mono text-xs">{policy.priority}</td>
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-900">{policy.name}</div>
                      <div className="text-xs text-slate-500">{policy.description}</div>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {policy.role ?? "any role"} · {policy.sensitivity ?? "any level"}
                      {policy.resource && ` · ${policy.resource}`}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {[
                        policy.min_trust_score > 0 &&
                          `score ≥ ${policy.min_trust_score}`,
                        policy.require_mfa && "MFA",
                        policy.require_known_device && "known device",
                        policy.deny_vpn && "no VPN",
                        policy.allowed_countries.length > 0 &&
                          policy.allowed_countries.join("/"),
                      ]
                        .filter(Boolean)
                        .join(", ") || "none"}
                    </td>
                    <td
                      className={`px-3 py-2 text-xs font-medium ${
                        policy.effect === "DENY"
                          ? "text-risk-critical"
                          : "text-emerald-700"
                      }`}
                    >
                      {policy.effect}
                    </td>
                    {writable && (
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => onToggle(policy)}
                            className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
                          >
                            {policy.enabled ? "Disable" : "Enable"}
                          </button>
                          <button
                            onClick={() => onDelete(policy)}
                            className="rounded border border-slate-300 px-2 py-1 text-xs text-risk-critical hover:bg-red-50"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </Page>
  );
}
