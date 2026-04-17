interface ToggleProps {
  value: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}

export function Toggle({ value, onChange, disabled }: ToggleProps) {
  return (
    <div
      onClick={disabled ? undefined : () => onChange(!value)}
      style={{
        width: "32px",
        height: "16px",
        borderRadius: "8px",
        background: value ? "var(--color-text-tertiary)" : "var(--color-text-ghost)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        position: "relative",
        transition: "background 0.2s",
        flexShrink: 0,
      }}
    >
      <div
        style={{
          width: "12px",
          height: "12px",
          borderRadius: "50%",
          background: value ? "var(--color-text-primary)" : "var(--color-text-muted)",
          position: "absolute",
          top: "2px",
          left: value ? "18px" : "2px",
          transition: "left 0.2s, background 0.2s",
        }}
      />
    </div>
  );
}
