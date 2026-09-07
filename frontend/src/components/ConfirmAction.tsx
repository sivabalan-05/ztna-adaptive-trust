import { useState } from "react";
import { Card } from "./layout/Page";

export interface ConfirmActionTextInput {
  label: string;
  placeholder?: string;
  defaultValue?: string;
  minLength?: number;
}

/**
 * In-app confirmation panel, standing in for `window.confirm`/`window.prompt`.
 *
 * Those block on a native dialog that some browser contexts (embedded panes,
 * sandboxed iframes without `allow-modals`) suppress outright — `confirm()`
 * then returns `false` immediately, so the action silently no-ops. This
 * renders inline instead, following the pattern already used by
 * RevocationPage: a `Card` titled with the specific action, an optional text
 * input for a reason/note, a confirm button, and a Cancel that clears state.
 */
export default function ConfirmAction({
  title,
  description,
  textInput,
  confirmLabel,
  destructive = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  description: string;
  textInput?: ConfirmActionTextInput;
  confirmLabel: string;
  destructive?: boolean;
  onConfirm: (value?: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(textInput?.defaultValue ?? "");
  const minLength = textInput?.minLength ?? 0;
  const disabled = Boolean(textInput) && value.trim().length < minLength;

  return (
    <Card title={title}>
      <div className="text-sm text-slate-700">{description}</div>

      {textInput && (
        <>
          <label className="mt-3 block text-sm font-medium text-slate-700">
            {textInput.label}
          </label>
          <input
            autoFocus
            value={value}
            placeholder={textInput.placeholder}
            onChange={(e) => setValue(e.target.value)}
            className="mt-1 w-full max-w-lg rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900"
          />
        </>
      )}

      <div className="mt-3 flex gap-2">
        <button
          onClick={() => onConfirm(textInput ? value : undefined)}
          disabled={disabled}
          className={`rounded-lg px-4 py-2 text-sm font-medium text-white disabled:opacity-50 ${
            destructive ? "bg-risk-critical" : "bg-shell"
          }`}
        >
          {confirmLabel}
        </button>
        <button
          onClick={onCancel}
          className="rounded-lg border border-slate-300 px-4 py-2 text-sm"
        >
          Cancel
        </button>
      </div>
    </Card>
  );
}
