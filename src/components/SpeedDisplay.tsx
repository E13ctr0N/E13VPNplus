function formatSpeed(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB/s`;
}

interface SpeedDisplayProps {
  speed: { down: number; up: number } | null;
  active: boolean;
}

export function SpeedDisplay({ speed, active }: SpeedDisplayProps) {
  const color = active ? "var(--color-speed)" : "var(--color-text-dim)";
  const arrowColor = active ? "var(--color-speed-arrow)" : "var(--color-text-dim)";

  return (
    <div style={{ display: "flex", gap: "16px" }}>
      <span style={{ fontSize: "10px", color, transition: "color 0.3s" }}>
        <span style={{ color: arrowColor, fontSize: "9px", transition: "color 0.3s" }}>↓</span>{" "}
        {speed ? formatSpeed(speed.down) : "0.0 KB/s"}
      </span>
      <span style={{ fontSize: "10px", color, transition: "color 0.3s" }}>
        <span style={{ color: arrowColor, fontSize: "9px", transition: "color 0.3s" }}>↑</span>{" "}
        {speed ? formatSpeed(speed.up) : "0.0 KB/s"}
      </span>
    </div>
  );
}
