interface PowerButtonProps {
  state: "off" | "connecting" | "on";
  onClick: () => void;
  disabled?: boolean;
}

export function PowerButton({ state, onClick, disabled }: PowerButtonProps) {
  const arcStroke = state === "on" ? "var(--color-power-arc-on)" : "var(--color-power-arc)";
  const lineStroke =
    state === "on" ? "var(--color-power-line-on)" : state === "connecting" ? "var(--color-power-line-connecting)" : "var(--color-power-line-off)";
  const lineWidth = state === "on" ? 2 : 1.5;
  const cursor = disabled ? "not-allowed" : "pointer";

  return (
    <div
      onClick={disabled ? undefined : onClick}
      style={{
        width: "80px",
        height: "80px",
        cursor,
        position: "relative",
      }}
    >
      <svg width="80" height="80" viewBox="0 0 80 80">
        <path
          d="M 28 18 A 24 24 0 1 0 52 18"
          fill="none"
          stroke={arcStroke}
          strokeWidth="1.5"
          strokeLinecap="round"
          style={{ transition: "stroke 0.3s" }}
        />
        <line
          x1="40" y1="12" x2="40" y2="30"
          stroke={lineStroke}
          strokeWidth={lineWidth}
          strokeLinecap="round"
          style={{ transition: "stroke 0.3s" }}
        />
      </svg>

      {state === "connecting" && (
        <style>{`
          @keyframes power-pulse {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 1; }
          }
          .power-pulse line { animation: power-pulse 1s ease-in-out infinite; }
        `}</style>
      )}
      {state === "connecting" && (
        <svg
          className="power-pulse"
          width="80" height="80" viewBox="0 0 80 80"
          style={{ position: "absolute", top: 0, left: 0 }}
        >
          <line
            x1="40" y1="12" x2="40" y2="30"
            stroke="var(--color-power-pulse)"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      )}
    </div>
  );
}
