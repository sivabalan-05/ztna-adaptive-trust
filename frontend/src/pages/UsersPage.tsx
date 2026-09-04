import { useCallback, useEffect, useState } from "react";
import {
  approveDevice, getAllDevices, getRoles, getUsers, revokeDevice, updateUser,
  type DeviceInfo, type RoleRow, type UserRow,
} from "../api/client";
import Page, { Card, Empty, RiskChip } from "../components/layout/Page";

export default function UsersPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"users" | "devices">("users");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getUsers(query).then(setUsers).catch(() => setUsers([]));
    getAllDevices().then(setDevices).catch(() => setDevices([]));
  }, [query]);

  useEffect(() => {
    getRoles().then(setRoles).catch(() => setRoles([]));
  }, []);
  useEffect(load, [load]);

  async function changeRole(user: UserRow, role: string) {
    setError(null);
    try {
      await updateUser(user.id, { role });
      load();
    } catch (e) {
      const detail = (e as { response?: { data?: { detail?: string } } }).response
        ?.data?.detail;
      setError(detail ?? "Could not update the user.");
    }
  }

  async function unlock(user: UserRow) {
    await updateUser(user.id, { unlock: true });
    load();
  }

  const pending = devices.filter((d) => d.status === "PENDING").length;

  return (
    <Page
      title="Users & devices"
      description="Roles set the clearance ceiling — no trust score lifts a role above it. Devices are trusted on first use and await approval."
      actions={
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search users…"
          className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
        />
      }
    >
      {error && (
        <div className="mb-4 rounded-lg bg-red-50 px-4 py-2.5 text-sm text-risk-critical">
          {error}
        </div>
      )}

      <div className="mb-4 flex gap-1">
        <button
          onClick={() => setTab("users")}
          className={`rounded-lg px-3 py-1.5 text-sm ${
            tab === "users"
              ? "bg-shell text-white"
              : "border border-slate-300 bg-white text-slate-700"
          }`}
        >
          Users ({users.length})
        </button>
        <button
          onClick={() => setTab("devices")}
          className={`rounded-lg px-3 py-1.5 text-sm ${
            tab === "devices"
              ? "bg-shell text-white"
              : "border border-slate-300 bg-white text-slate-700"
          }`}
        >
          Devices ({devices.length}
          {pending > 0 && `, ${pending} pending`})
        </button>
      </div>

      {tab === "users" ? (
        <Card>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Role</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">MFA</th>
                  <th className="px-3 py-2 font-medium">Devices</th>
                  <th className="px-3 py-2 font-medium">Sessions</th>
                  <th className="px-3 py-2 font-medium">Latest trust</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {users.map((user) => (
                  <tr key={user.id}>
                    <td className="px-3 py-2.5">
                      <div className="font-medium text-slate-900">
                        {user.full_name}
                      </div>
                      <div className="text-xs text-slate-500">
                        {user.username} · {user.department || "—"}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <select
                        value={user.role}
                        onChange={(e) => changeRole(user, e.target.value)}
                        className="rounded border border-slate-300 bg-white px-2 py-1 text-xs"
                        aria-label={`Role for ${user.username}`}
                      >
                        {roles.map((role) => (
                          <option key={role.name} value={role.name}>
                            {role.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-3 py-2.5">
                      {user.is_locked ? (
                        <span className="text-risk-critical">LOCKED</span>
                      ) : (
                        <span className="text-slate-600">
                          {user.account_status}
                        </span>
                      )}
                      {user.failed_login_count > 0 && (
                        <div className="text-[11px] text-slate-500">
                          {user.failed_login_count} failed
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-slate-600">
                      {user.mfa_enrolled ? "enrolled" : "not enrolled"}
                    </td>
                    <td className="px-3 py-2.5 tabular-nums text-slate-600">
                      {user.device_count}
                    </td>
                    <td className="px-3 py-2.5 tabular-nums text-slate-600">
                      {user.active_sessions}
                    </td>
                    <td className="px-3 py-2.5">
                      {user.latest_risk_level ? (
                        <RiskChip
                          level={user.latest_risk_level}
                          score={user.latest_trust_score ?? undefined}
                        />
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      {user.is_locked && (
                        <button
                          onClick={() => unlock(user)}
                          className="rounded border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50"
                        >
                          Unlock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : (
        <Card>
          {devices.length === 0 ? (
            <Empty>No devices registered.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">Device</th>
                    <th className="px-3 py-2 font-medium">Status</th>
                    <th className="px-3 py-2 font-medium">Trusted</th>
                    <th className="px-3 py-2 font-medium">Seen</th>
                    <th className="px-3 py-2 font-medium">Last used</th>
                    <th className="px-3 py-2" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {devices.map((device) => (
                    <tr key={device.id}>
                      <td className="px-3 py-2.5">
                        <div className="font-medium text-slate-900">
                          {device.label}
                        </div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {device.fingerprint.slice(0, 24)}…
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        <span
                          className={
                            device.status === "APPROVED"
                              ? "text-emerald-700"
                              : device.status === "PENDING"
                                ? "text-orange-700"
                                : "text-risk-critical"
                          }
                        >
                          {device.status}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-slate-600">
                        {device.is_trusted ? "yes" : "no"}
                      </td>
                      <td className="px-3 py-2.5 tabular-nums text-slate-600">
                        {device.seen_count}×
                      </td>
                      <td className="px-3 py-2.5 text-xs text-slate-600">
                        {new Date(device.last_seen_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        {device.status !== "APPROVED" && (
                          <button
                            onClick={() =>
                              approveDevice(device.id).then(load)
                            }
                            className="mr-1 rounded border border-emerald-300 px-2.5 py-1 text-xs text-emerald-700 hover:bg-emerald-50"
                          >
                            Approve
                          </button>
                        )}
                        {device.status !== "REVOKED" && (
                          <button
                            onClick={() => revokeDevice(device.id).then(load)}
                            className="rounded border border-red-200 px-2.5 py-1 text-xs text-risk-critical hover:bg-red-50"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </Page>
  );
}
