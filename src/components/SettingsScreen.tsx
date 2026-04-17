import { enable, disable } from "@tauri-apps/plugin-autostart";
import { useT, useI18n, Lang } from "../i18n";
import { Toggle } from "./Toggle";

type Theme = "dark" | "light";

interface SettingsScreenProps {
  autostart: boolean;
  setAutostart: (v: boolean) => void;
  autoReconnect: boolean;
  setAutoReconnect: (v: boolean) => void;
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
        overflow: "hidden",
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
            } catch {}
          }}
        />
      </SettingRow>

      <SettingRow label={t("settings.auto_reconnect")} description={t("settings.auto_reconnect_desc")}>
        <Toggle value={autoReconnect} onChange={setAutoReconnect} />
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
