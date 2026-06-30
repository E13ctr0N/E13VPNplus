import { enable, disable } from "@tauri-apps/plugin-autostart";
import { useT, useI18n, Lang } from "../i18n";
import { Toggle } from "./Toggle";

type Theme = "dark" | "light";

interface SettingsScreenProps {
  autostart: boolean;
  setAutostart: (v: boolean) => void;
  autoReconnect: boolean;
  setAutoReconnect: (v: boolean) => void;
  autoConnectOnAutostart: boolean;
  setAutoConnectOnAutostart: (v: boolean) => void;
  proxyUseSystemProxy: boolean;
  setProxyUseSystemProxy: (v: boolean) => void;
  proxyRandomPort: boolean;
  setProxyRandomPort: (v: boolean) => void;
  proxyFixedPort: number;
  setProxyFixedPort: (v: number) => void;
  uiScale: 100 | 125 | 150;
  setUiScale: (v: 100 | 125 | 150) => void;
  theme: Theme;
  setTheme: (v: Theme) => void;
}

export function SettingsScreen({
  autostart,
  setAutostart,
  autoReconnect,
  setAutoReconnect,
  autoConnectOnAutostart,
  setAutoConnectOnAutostart,
  proxyUseSystemProxy,
  setProxyUseSystemProxy,
  proxyRandomPort,
  setProxyRandomPort,
  proxyFixedPort,
  setProxyFixedPort,
  uiScale,
  setUiScale,
  theme,
  setTheme,
}: SettingsScreenProps) {
  const t = useT();
  const { lang, setLang } = useI18n();

  return (
    <div
      style={{
        flex: 1,
        overflowY: "auto",
        padding: "14px",
        display: "flex",
        flexDirection: "column",
        gap: "4px",
      }}
    >
      <SettingRow label={t("settings.theme")}>
        <FlatSelector<Theme>
          options={[
            { value: "dark", label: t("settings.theme_dark") },
            { value: "light", label: t("settings.theme_light") },
          ]}
          active={theme}
          onChange={setTheme}
        />
      </SettingRow>

      <SettingRow label={t("settings.scale")}>
        <FlatSelector<100 | 125 | 150>
          options={[
            { value: 100, label: "100%" },
            { value: 125, label: "125%" },
            { value: 150, label: "150%" },
          ]}
          active={uiScale}
          onChange={setUiScale}
        />
      </SettingRow>

      <SettingRow label={t("settings.autostart")} description={t("settings.autostart_desc")}>
        <Toggle
          value={autostart}
          onChange={async (v) => {
            try {
              if (v) await enable();
              else await disable();
              setAutostart(v);
              if (!v) setAutoConnectOnAutostart(false);
            } catch {}
          }}
        />
      </SettingRow>

      <SettingRow label={t("settings.auto_connect_start")} description={t("settings.auto_connect_start_desc")}>
        <Toggle
          value={autoConnectOnAutostart}
          disabled={!autostart}
          onChange={async (v) => {
            if (v && autostart) {
              try {
                await enable();
              } catch {}
            }
            setAutoConnectOnAutostart(v);
          }}
        />
      </SettingRow>

      <SettingRow label={t("settings.auto_reconnect")} description={t("settings.auto_reconnect_desc")}>
        <Toggle value={autoReconnect} onChange={setAutoReconnect} />
      </SettingRow>

      <SettingRow label={t("settings.proxy_system")} description={t("settings.proxy_system_desc")}>
        <Toggle value={proxyUseSystemProxy} onChange={setProxyUseSystemProxy} />
      </SettingRow>

      <SettingRow label={t("settings.proxy_random_port")} description={t("settings.proxy_random_port_desc")}>
        <Toggle value={proxyRandomPort} onChange={setProxyRandomPort} />
      </SettingRow>

      <SettingRow label={t("settings.proxy_fixed_port")} description={t("settings.proxy_fixed_port_desc")}>
        <input
          type="number"
          min={1024}
          max={65534}
          step={1}
          value={proxyFixedPort}
          disabled={proxyRandomPort}
          onChange={(e) => {
            const next = Math.trunc(Number(e.currentTarget.value));
            if (Number.isFinite(next)) {
              setProxyFixedPort(Math.max(1024, Math.min(65534, next)));
            }
          }}
          style={{
            width: "72px",
            height: "24px",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-sm)",
            background: "var(--color-surface-hover)",
            color: proxyRandomPort ? "var(--color-text-ghost)" : "var(--color-text-secondary)",
            fontFamily: "var(--font-system)",
            fontSize: "10px",
            padding: "0 6px",
            outline: "none",
            opacity: proxyRandomPort ? 0.45 : 1,
          }}
        />
      </SettingRow>

      <SettingRow label={t("settings.language")}>
        <FlatSelector<Lang>
          options={[
            { value: "ru", label: "RU" },
            { value: "en", label: "EN" },
          ]}
          active={lang}
          onChange={setLang}
        />
      </SettingRow>
    </div>
  );
}


function SettingRow({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "7px 10px",
        borderRadius: "var(--radius-sm)",
        transition: "background 0.1s",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--color-surface)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      <div>
        <div style={{ fontSize: "11px", color: "var(--color-text-secondary)" }}>{label}</div>
        {description && (
          <div style={{ fontSize: "9px", color: "var(--color-text-dim)", marginTop: "1px" }}>
            {description}
          </div>
        )}
      </div>
      {children}
    </div>
  );
}

function FlatSelector<T extends string | number>({
  options,
  active,
  onChange,
}: {
  options: { value: T; label: string; disabled?: boolean }[];
  active: T;
  onChange: (v: T) => void;
}) {
  return (
    <div style={{ display: "flex", gap: "2px" }}>
      {options.map((opt) => (
        <button
          key={String(opt.value)}
          onClick={opt.disabled ? undefined : () => onChange(opt.value)}
          style={{
            padding: "3px 10px",
            fontSize: "9px",
            fontWeight: 500,
            fontFamily: "var(--font-system)",
            borderRadius: "var(--radius-sm)",
            border: "none",
            background: active === opt.value ? "var(--color-surface-hover)" : "transparent",
            color: opt.disabled
              ? "var(--color-text-ghost)"
              : active === opt.value
              ? "var(--color-text-secondary)"
              : "var(--color-text-dim)",
            cursor: opt.disabled ? "not-allowed" : "pointer",
            opacity: opt.disabled ? 0.5 : 1,
            transition: "background 0.15s, color 0.15s",
          }}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}
