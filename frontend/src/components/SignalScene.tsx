/** A CSS 3D model of a continuously verified access network. */
export default function SignalScene({ compact = false }: { compact?: boolean }) {
  return (
    <div
      className={`signal-scene${compact ? " signal-scene-compact" : ""}`}
      aria-hidden="true"
    >
      <div className="signal-scene-grid" />
      <div className="signal-scene-orbit signal-orbit-one">
        <i /><i /><i />
      </div>
      <div className="signal-scene-orbit signal-orbit-two">
        <i /><i />
      </div>
      <div className="signal-scene-orbit signal-orbit-three">
        <i />
      </div>
      <div className="signal-scene-core">
        <div className="signal-core-halo" />
        <svg viewBox="0 0 64 64" role="presentation">
          <path d="M32 7 51 15v14c0 13-8 23-19 29C21 52 13 42 13 29V15L32 7Z" />
          <path d="m23 31 6 6 13-14" />
        </svg>
      </div>
      <div className="signal-scene-label signal-label-identity"><span />Identity</div>
      <div className="signal-scene-label signal-label-device"><span />Device</div>
      <div className="signal-scene-label signal-label-policy"><span />Policy</div>
      <div className="signal-scene-label signal-label-resource"><span />Resource</div>
      <div className="signal-scene-caption">Every request, re-verified</div>
    </div>
  );
}
