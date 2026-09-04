/**
 * Device fingerprint: a stable SHA-256 over the properties a browser exposes
 * about the machine it runs on.
 *
 * This is an *identifying* signal, not a secret. It cannot authenticate anyone
 * on its own — anything the browser reports, an attacker can forge. Its value
 * is that forging it correctly requires knowing the victim's exact environment,
 * so a mismatch is strong evidence that a token has moved to another machine.
 * The backend treats an unknown fingerprint as a risk input to the trust score,
 * never as an automatic block.
 */

const STORAGE_KEY = "ztna.device.fingerprint";

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Renders text and a gradient; the exact pixels vary by GPU, driver and fonts. */
function canvasHash(): string {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "no-canvas";

    ctx.textBaseline = "top";
    ctx.font = "16px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(0, 0, 120, 30);
    ctx.fillStyle = "#069";
    ctx.fillText("ZTNA-fingerprint-✓", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("ZTNA-fingerprint-✓", 4, 20);
    return canvas.toDataURL();
  } catch {
    return "canvas-blocked";
  }
}

function webglHash(): string {
  try {
    const canvas = document.createElement("canvas");
    const gl =
      (canvas.getContext("webgl") as WebGLRenderingContext | null) ??
      (canvas.getContext("experimental-webgl") as WebGLRenderingContext | null);
    if (!gl) return "no-webgl";

    const info = gl.getExtension("WEBGL_debug_renderer_info");
    const vendor = info
      ? String(gl.getParameter(info.UNMASKED_VENDOR_WEBGL))
      : String(gl.getParameter(gl.VENDOR));
    const renderer = info
      ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL))
      : String(gl.getParameter(gl.RENDERER));
    return `${vendor}~${renderer}`;
  } catch {
    return "webgl-blocked";
  }
}

export interface DeviceSignals {
  fingerprint: string;
  platform: string;
  screen: string;
  timezone: string;
  language: string;
}

let cached: DeviceSignals | null = null;

export async function collectDeviceSignals(): Promise<DeviceSignals> {
  if (cached) return cached;

  const platform = navigator.platform || "unknown";
  const screenSize = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown";
  const language = navigator.language || "unknown";

  const material = [
    navigator.userAgent,
    platform,
    screenSize,
    timezone,
    language,
    String(navigator.hardwareConcurrency ?? "?"),
    canvasHash(),
    webglHash(),
  ].join("|");

  let fingerprint: string;
  try {
    fingerprint = await sha256Hex(material);
  } catch {
    // crypto.subtle needs a secure context. Fall back to a stored random id so
    // the app still works over plain HTTP on a LAN demo, and say so plainly:
    // this value identifies the browser, it does not describe the machine.
    const existing = localStorage.getItem(STORAGE_KEY);
    if (existing) {
      fingerprint = existing;
    } else {
      const random = crypto.getRandomValues(new Uint8Array(32));
      fingerprint = Array.from(random)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      localStorage.setItem(STORAGE_KEY, fingerprint);
    }
  }

  cached = { fingerprint, platform, screen: screenSize, timezone, language };
  return cached;
}
