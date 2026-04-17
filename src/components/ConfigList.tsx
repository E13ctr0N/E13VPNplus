import { useState } from "react";
import { useT } from "../i18n";

export interface VlessConfig {
  id: string;
  name: string;
  uri: string;
}

export function parseConfigHost(uri: string): string {
  try {
    const s = uri.replace("vless://", "");
    const afterAt = s.split("@")[1] ?? "";
    const hostPort = afterAt.split("?")[0] ?? "";
    return hostPort.replace(/:\d+$/, "");
  } catch {
    return "";
  }
}

interface ConfigListProps {
  configs: VlessConfig[];
  activeId: string | null;
  connected: boolean;
  onSelect: (id: string) => void;
  onRemove: (id: string) => void;
  onPaste: () => void;
}

export function ConfigList({ configs, activeId, connected, onSelect, onRemove, onPaste }: ConfigListProps) {
  const t = useT();
  const [confirmId, setConfirmId] = useState<string | null>(null);
  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "6px", overflow: "hidden" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
        <span style={{ fontSize: "9px", textTransform: "uppercase", letterSpacing: "1.5px", color: "var(--color-text-muted)", fontWeight: 600 }}>
          {t("vpn.servers")}
        </span>
        <span
          onClick={connected ? undefined : onPaste}
          style={{
            fontSize: "9px",
            color: configs.length === 0 && !connected ? "var(--color-success-text)" : "var(--color-text-muted)",
            cursor: connected ? "default" : "pointer",
            padding: "2px 8px",
            borderRadius: "3px",
            opacity: connected ? 0.3 : 1,
            transition: "color 0.3s, opacity 0.15s",
          }}
          onMouseEnter={(e) => { if (!connected) e.currentTarget.style.background = "var(--color-surface-hover)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
        >
          {t("vpn.paste")}
        </span>
      </div>

      <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "2px" }}>
        {configs.length === 0 ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <span style={{ fontSize: "10px", color: "var(--color-text-dim)" }}>{t("vpn.paste_hint")}</span>
          </div>
        ) : (
          configs.map((cfg) => {
            const isActive = cfg.id === activeId;
            const isConnected = isActive && connected;
            const isDimmed = connected && !isActive;

            return (
              <div
                key={cfg.id}
                onClick={() => !connected && onSelect(cfg.id)}
                className="cfg-row"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "9px 10px",
                  borderRadius: "6px",
                  cursor: connected ? "default" : "pointer",
                  background: isActive ? (isConnected ? "var(--color-surface-active)" : "var(--color-surface)") : "transparent",
                  opacity: isDimmed ? 0.4 : 1,
                  transition: "background 0.1s, opacity 0.3s",
                }}
                onMouseEnter={(e) => {
                  if (!connected && !isActive) e.currentTarget.style.background = "var(--color-surface)";
                  const btn = e.currentTarget.querySelector<HTMLElement>(".remove-btn");
                  if (btn && confirmId !== cfg.id) btn.style.opacity = "1";
                }}
                onMouseLeave={(e) => {
                  if (!isActive) e.currentTarget.style.background = "transparent";
                  const btn = e.currentTarget.querySelector<HTMLElement>(".remove-btn");
                  if (btn && confirmId !== cfg.id) btn.style.opacity = "0";
                  setConfirmId(null);
                }}
              >
                <div style={{
                  width: "5px", height: "5px", borderRadius: "50%", flexShrink: 0,
                  background: isConnected ? "var(--color-accent)" : isActive ? "var(--color-text-tertiary)" : "var(--color-text-ghost)",
                  transition: "background 0.3s",
                }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: "11px", fontWeight: 500,
                    color: isConnected ? "var(--color-text-primary)" : isActive ? "var(--color-text-secondary)" : "var(--color-text-muted)",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", transition: "color 0.3s",
                  }}>
                    {cfg.name}
                  </div>
                  <div style={{
                    fontSize: "9px", fontFamily: "var(--font-mono)", marginTop: "1px",
                    color: isConnected ? "var(--color-text-muted)" : isActive ? "var(--color-text-dim)" : "var(--color-text-ghost)",
                    transition: "color 0.3s",
                  }}>
                    {parseConfigHost(cfg.uri)}
                  </div>
                </div>
                {!connected && (
                  <div
                    className="remove-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (confirmId === cfg.id) {
                        onRemove(cfg.id);
                        setConfirmId(null);
                      } else {
                        setConfirmId(cfg.id);
                      }
                    }}
                    style={{
                      width: "18px", height: "18px", borderRadius: "4px",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      color: confirmId === cfg.id ? "var(--color-error-text)" : "var(--color-text-dim)",
                      cursor: "pointer",
                      opacity: confirmId === cfg.id ? 1 : 0,
                      transition: "opacity 0.1s, color 0.1s", fontSize: "12px",
                    }}
                  >
                    ×
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
