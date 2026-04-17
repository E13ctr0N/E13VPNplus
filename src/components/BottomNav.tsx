import { useT } from "../i18n";

export type Tab = "vpn" | "routes" | "logs" | "settings";

interface BottomNavProps {
  active: Tab;
  onChange: (tab: Tab) => void;
}

export function BottomNav({ active, onChange }: BottomNavProps) {
  const t = useT();

  return (
    <div
      style={{
        height: "32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "24px",
        borderTop: "1px solid var(--color-border)",
        background: "var(--color-titlebar)",
        flexShrink: 0,
      }}
    >
      <NavItem label={t("nav.vpn")} active={active === "vpn"} onClick={() => onChange("vpn")} />
      <NavItem label={t("nav.routes")} active={active === "routes"} onClick={() => onChange("routes")} />
      <NavItem label={t("nav.logs")} active={active === "logs"} onClick={() => onChange("logs")} />
      <NavItem label={t("nav.settings")} active={active === "settings"} onClick={() => onChange("settings")} />
    </div>
  );
}

function NavItem({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <span
      onClick={onClick}
      style={{
        fontSize: "9px",
        cursor: "pointer",
        color: active ? "var(--color-text-secondary)" : "var(--color-text-dim)",
        borderBottom: active ? "1px solid var(--color-text-tertiary)" : "1px solid transparent",
        paddingBottom: "1px",
        transition: "color 0.15s, border-color 0.15s",
      }}
      onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = "var(--color-text-muted)"; }}
      onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = "var(--color-text-dim)"; }}
    >
      {label}
    </span>
  );
}
