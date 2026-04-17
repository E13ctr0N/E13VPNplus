import { getCurrentWindow } from "@tauri-apps/api/window";

const win = getCurrentWindow();

const APP_VERSION = __APP_VERSION__;

export function Titlebar({ connected, showVersion }: { connected?: boolean; showVersion?: boolean }) {
  return (
    <div
      data-tauri-drag-region
      style={{
        height: "36px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 14px",
        background: "var(--color-titlebar)",
        borderBottom: "1px solid var(--color-border)",
        flexShrink: 0,
      }}
    >
      <span
        data-tauri-drag-region
        style={{
          fontSize: "12px",
          fontWeight: 500,
          color: connected ? "var(--color-text-tertiary)" : "var(--color-text-muted)",
          transition: "color 0.3s",
        }}
      >
        E13VPN
        {showVersion && (
          <span style={{ fontSize: "10px", fontWeight: 400, color: "var(--color-text-ghost)", marginLeft: "6px" }}>
            v{APP_VERSION}
          </span>
        )}
      </span>

      <div style={{ display: "flex", gap: "7px" }}>
        <WinBtn onClick={() => win.minimize()} />
        <WinBtn onClick={() => win.close()} danger />
      </div>
    </div>
  );
}

function WinBtn({ onClick, danger }: { onClick: () => void; danger?: boolean }) {
  return (
    <div
      onClick={onClick}
      style={{
        width: "10px",
        height: "10px",
        borderRadius: "50%",
        background: danger ? "var(--color-danger)" : "var(--color-text-ghost)",
        cursor: "pointer",
        transition: "opacity 0.15s",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.7")}
      onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
    />
  );
}
