import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  apiErrorMessage, createResource, disableResource, getResources,
  updateResource, uploadResourceFile, type ResourceReachability,
} from "../api/client";
import { usePermissions } from "../auth/usePermissions";
import Page, { Card, Empty } from "../components/layout/Page";

const SENSITIVITIES = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];

const EMPTY_FORM = {
  slug: "", name: "", description: "", category: "application",
  sensitivity: "INTERNAL", owner: "",
};

/**
 * The catalogue, as an administrator sees it: what exists, what it protects,
 * and what file sits behind it. Analysts get the same view without controls.
 *
 * Loaded with `includeDisabled` so a disabled resource stays visible (and
 * recoverable via Enable) instead of vanishing the moment it is disabled —
 * disabling is a soft-delete on the backend, not a real deletion.
 */
export default function ResourcesAdminPage() {
  const { can } = usePermissions();
  const writable = can("resources:write");
  const [resources, setResources] = useState<ResourceReachability[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);

  const load = useCallback(() => {
    getResources(true).then(setResources).catch(() => setResources([]));
  }, []);

  useEffect(load, [load]);

  async function onCreate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createResource(form);
      setForm(EMPTY_FORM);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not create the resource."));
    } finally {
      setBusy(false);
    }
  }

  async function onUpload(slug: string, file: File) {
    setError("");
    try {
      await uploadResourceFile(slug, file);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Upload failed."));
    }
  }

  async function onDisable(slug: string) {
    setError("");
    try {
      await disableResource(slug);
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not disable the resource."));
    }
  }

  async function onEnable(slug: string) {
    setError("");
    try {
      await updateResource(slug, { enabled: true });
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not re-enable the resource."));
    }
  }

  async function onSetFloor(slug: string, value: number) {
    setError("");
    try {
      await updateResource(slug, { min_trust_score: value });
      load();
    } catch (err) {
      setError(apiErrorMessage(err, "Could not update the resource."));
    }
  }

  return (
    <Page
      title="Resources"
      description="The protected catalogue. A resource's sensitivity and trust floor decide who reaches it; the attached file is what they receive."
    >
      {error && (
        <div className="mb-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-risk-critical">
          {error}
        </div>
      )}

      {writable && (
        <div className="mb-4">
          <Card title="Publish a resource">
            <form onSubmit={onCreate} className="grid gap-3 sm:grid-cols-2">
              <input
                required
                placeholder="slug (lowercase, hyphens)"
                pattern="[a-z0-9-]+"
                value={form.slug}
                onChange={(e) => setForm({ ...form, slug: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <input
                required
                placeholder="Display name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <input
                placeholder="Description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm sm:col-span-2"
              />
              <input
                placeholder="Owner (team)"
                value={form.owner}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <select
                value={form.sensitivity}
                onChange={(e) => setForm({ ...form, sensitivity: e.target.value })}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Sensitivity"
              >
                {SENSITIVITIES.map((level) => (
                  <option key={level} value={level}>{level}</option>
                ))}
              </select>
              <button
                type="submit"
                disabled={busy}
                className="rounded-lg bg-shell px-4 py-2 text-sm font-medium text-white disabled:opacity-50 sm:col-span-2"
              >
                {busy ? "Publishing…" : "Publish resource"}
              </button>
            </form>
            <p className="mt-2 text-xs text-slate-500">
              The trust floor defaults to the sensitivity's own minimum. Attach a
              file below once the resource exists.
            </p>
          </Card>
        </div>
      )}

      <Card title={`Catalogue (${resources.length})`}>
        {resources.length === 0 ? (
          <Empty>No resources published yet.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Resource</th>
                  <th className="px-3 py-2 font-medium">Sensitivity</th>
                  <th className="px-3 py-2 font-medium">Floor</th>
                  <th className="px-3 py-2 font-medium">File</th>
                  {writable && <th className="px-3 py-2 font-medium">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {resources.map((resource) => (
                  <tr
                    key={resource.id}
                    className={resource.enabled ? "" : "opacity-50"}
                  >
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-900">
                        {resource.name}
                        {!resource.enabled && (
                          <span className="ml-2 rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-600">
                            Disabled
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {resource.slug} · {resource.owner}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-700">
                      {resource.sensitivity}
                    </td>
                    <td className="px-3 py-2">
                      {writable ? (
                        <input
                          type="number"
                          min={0}
                          max={100}
                          defaultValue={resource.min_trust_score}
                          onBlur={(e) => {
                            const value = Number(e.target.value);
                            if (value !== resource.min_trust_score) {
                              onSetFloor(resource.slug, value);
                            }
                          }}
                          className="w-20 rounded border border-slate-300 px-2 py-1 font-mono text-xs"
                          aria-label={`Trust floor for ${resource.name}`}
                        />
                      ) : (
                        <span className="font-mono text-xs">
                          {resource.min_trust_score}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {resource.has_file ? (
                        <>
                          {resource.file_name}
                          <span className="ml-1 text-slate-400">
                            ({resource.content_type})
                          </span>
                        </>
                      ) : (
                        <span className="text-amber-700">no file</span>
                      )}
                    </td>
                    {writable && (
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <label className="cursor-pointer rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50">
                            {resource.has_file ? "Replace" : "Upload"}
                            <input
                              type="file"
                              className="hidden"
                              onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (file) onUpload(resource.slug, file);
                                e.target.value = "";
                              }}
                            />
                          </label>
                          {resource.enabled ? (
                            <button
                              onClick={() => onDisable(resource.slug)}
                              className="rounded border border-slate-300 px-2 py-1 text-xs text-risk-critical hover:bg-red-50"
                            >
                              Disable
                            </button>
                          ) : (
                            <button
                              onClick={() => onEnable(resource.slug)}
                              className="rounded border border-emerald-300 px-2 py-1 text-xs text-emerald-700 hover:bg-emerald-50"
                            >
                              Enable
                            </button>
                          )}
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
