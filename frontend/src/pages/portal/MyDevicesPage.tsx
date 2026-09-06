import { useEffect, useState } from "react";
import { getMyDevices, type DeviceInfo } from "../../api/client";
import Page, { Card, Empty } from "../../components/layout/Page";

const STATUS_STYLES: Record<string, string> = {
  APPROVED: "text-emerald-700",
  PENDING: "text-amber-700",
  REVOKED: "text-risk-critical",
  BLOCKED: "text-risk-critical",
};

/**
 * The devices this account has signed in from.
 *
 * Device standing is not cosmetic: an unrecognised fingerprint costs trust
 * score, which is often what puts a higher-sensitivity resource out of reach.
 */
export default function MyDevicesPage() {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);

  useEffect(() => {
    getMyDevices().then(setDevices).catch(() => setDevices([]));
  }, []);

  const pending = devices.filter((device) => device.status === "PENDING").length;

  return (
    <Page
      title="My devices"
      description="Every device you have signed in from. An unapproved device lowers your trust score until an administrator approves it."
    >
      {pending > 0 && (
        <div className="mb-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900">
          {pending === 1
            ? "One of your devices is awaiting administrator approval."
            : `${pending} of your devices are awaiting administrator approval.`}{" "}
          Until then your trust score carries a device penalty.
        </div>
      )}

      <Card title={`Registered devices (${devices.length})`}>
        {devices.length === 0 ? (
          <Empty>No devices registered.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Device</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Times seen</th>
                  <th className="px-3 py-2 font-medium">First seen</th>
                  <th className="px-3 py-2 font-medium">Last used</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {devices.map((device) => (
                  <tr key={device.id}>
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-900">{device.label}</div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {device.fingerprint.slice(0, 24)}…
                      </div>
                    </td>
                    <td className={`px-3 py-2 ${STATUS_STYLES[device.status] ?? ""}`}>
                      {device.status}
                    </td>
                    <td className="px-3 py-2 text-slate-600">{device.seen_count}×</td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {new Date(device.first_seen_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {new Date(device.last_seen_at).toLocaleString()}
                    </td>
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
