import { useState, useEffect, useRef } from "react";
import { load as loadStore, Store } from "@tauri-apps/plugin-store";
import { invoke } from "@tauri-apps/api/core";
import { useT } from "../i18n";

const STORE_FILE = "vpn.json";

export function RoutesScreen() {
  const t = useT();
  const [bypass, setBypass] = useState<string[]>([]);
  const [bypassApps, setBypassApps] = useState<string[]>([]);
  const [inputSites, setInputSites] = useState("");
  const [inputApps, setInputApps] = useState("");
  const [siteError, setSiteError] = useState("");
  const [storeReady, setStoreReady] = useState(false);
  const sitesRef = useRef<HTMLInputElement>(null);
  const appsRef = useRef<HTMLInputElement>(null);
  const storeRef = useRef<Store | null>(null);

  useEffect(() => {
    loadStore(STORE_FILE, { autoSave: false, defaults: {} }).then(async (store) => {
      storeRef.current = store;
      const rawBypass = (await store.get<string[]>("routes_bypass")) ?? [];
      const rawApps = (await store.get<string[]>("routes_bypass_apps")) ?? [];
      // Мигрируем старые записи: нормализация + дедупликация (.ru → ru)
      const normalized: string[] = [];
      for (const entry of rawBypass) {
        try {
          const [norm, valid] = await invoke<[string, boolean]>("validate_route", { entry });
          if (valid && !normalized.includes(norm)) normalized.push(norm);
        } catch { /* skip invalid */ }
      }
      setBypass(normalized);
      setBypassApps(rawApps);
      setStoreReady(true);
    });
  }, []);

  useEffect(() => {
    if (!storeReady || !storeRef.current) return;
    const store = storeRef.current;
    (async () => {
      await store.set("routes_bypass", bypass);
      await store.set("routes_bypass_apps", bypassApps);
      await store.save();
    })();
  }, [bypass, bypassApps, storeReady]);

  async function addSite() {
    const raw = inputSites.trim();
    if (!raw) return;
    setSiteError("");
    try {
      const [norm, valid] = await invoke<[string, boolean]>("validate_route", { entry: raw });
      if (!valid) {
        setSiteError(t("routes.invalid_entry"));
        return;
      }
      setBypass((prev) => (prev.includes(norm) ? prev : [...prev, norm]));
      setInputSites("");
    } catch {
      setSiteError(t("routes.invalid_entry"));
    }
    sitesRef.current?.focus();
  }

  function addApp() {
    const val = inputApps.trim().toLowerCase();
    if (!val) return;
    setBypassApps((prev) => (prev.includes(val) ? prev : [...prev, val]));
    setInputApps("");
    appsRef.current?.focus();
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Two-column list */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        <RouteColumn
          title={t("routes.sites")}
          accent="var(--color-text-muted)"
          entries={bypass}
          onRemove={(i) => setBypass((prev) => prev.filter((_, idx) => idx !== i))}
          emptyText={t("routes.empty")}
        />
        <div style={{ width: "1px", background: "var(--color-border)", flexShrink: 0 }} />
        <RouteColumn
          title={t("routes.apps")}
          accent="var(--color-text-muted)"
          entries={bypassApps}
          onRemove={(i) => setBypassApps((prev) => prev.filter((_, idx) => idx !== i))}
          emptyText={t("routes.empty")}
        />
      </div>

      {/* Input area */}
      <div
        style={{
          borderTop: "1px solid var(--color-border)",
          padding: "8px 12px",
          background: "var(--color-surface)",
          flexShrink: 0,
          display: "flex",
          flexDirection: "column",
          gap: "6px",
        }}
      >
        {/* Sites input */}
        <InputRow
          inputRef={sitesRef}
          value={inputSites}
          onChange={(v) => { setInputSites(v); setSiteError(""); }}
          onAdd={addSite}
          placeholder={t("routes.site_placeholder")}
          color="var(--color-text-muted)"
          error={siteError}
        />
        {/* Apps input */}
        <InputRow
          inputRef={appsRef}
          value={inputApps}
          onChange={setInputApps}
          onAdd={addApp}
          placeholder={t("routes.app_placeholder")}
          color="var(--color-text-muted)"
        />
      </div>
    </div>
  );
}

function InputRow({
  inputRef,
  value,
  onChange,
  onAdd,
  placeholder,
  color,
  error,
}: {
  inputRef: React.RefObject<HTMLInputElement | null>;
  value: string;
  onChange: (v: string) => void;
  onAdd: () => void;
  placeholder: string;
  color: string;
  error?: string;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
      <div style={{ display: "flex", gap: "6px" }}>
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onAdd()}
          placeholder={placeholder}
          style={{
            flex: 1,
            height: "30px",
            background: "var(--color-surface-hover)",
            border: `1px solid ${error ? "#e53935" : "var(--color-border)"}`,
            borderRadius: "var(--radius-sm)",
            color: "var(--color-text)",
            fontFamily: "var(--font-system)",
            fontSize: "11px",
            padding: "0 8px",
            outline: "none",
            userSelect: "text",
          }}
          onFocus={(e) => (e.currentTarget.style.borderColor = error ? "#e53935" : color)}
          onBlur={(e) => (e.currentTarget.style.borderColor = error ? "#e53935" : "var(--color-border)")}
        />
        <button
          onClick={onAdd}
          style={{
            width: "30px",
            height: "30px",
            border: "none",
            borderRadius: "var(--radius-sm)",
            background: "var(--color-text-muted)",
            color: "var(--color-btn-text)",
            cursor: "pointer",
            fontFamily: "var(--font-system)",
            fontSize: "16px",
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            transition: "opacity 0.1s",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.8")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
        >
          +
        </button>
      </div>
      {error && (
        <span style={{ fontSize: "9px", color: "#e53935", padding: "0 2px" }}>{error}</span>
      )}
    </div>
  );
}

function RouteColumn({
  title,
  accent,
  entries,
  onRemove,
  emptyText,
}: {
  title: string;
  accent: string;
  entries: string[];
  onRemove: (i: number) => void;
  emptyText: string;
}) {
  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div
        style={{
          padding: "6px 10px",
          fontSize: "9px",
          letterSpacing: "0.12em",
          color: accent,
          borderBottom: "1px solid var(--color-border)",
          background: "var(--color-surface)",
          flexShrink: 0,
        }}
      >
        {title}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "2px 0" }}>
        {entries.length === 0 ? (
          <div
            style={{
              padding: "16px 10px",
              fontSize: "10px",
              color: "var(--color-text-muted)",
              opacity: 0.5,
              textAlign: "center",
            }}
          >
            {emptyText}
          </div>
        ) : (
          entries.map((entry, i) => (
            <RouteEntry key={i} value={entry} onRemove={() => onRemove(i)} />
          ))
        )}
      </div>
    </div>
  );
}

function RouteEntry({ value, onRemove }: { value: string; onRemove: () => void }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        padding: "4px 8px 4px 10px",
        gap: "4px",
      }}
      onMouseEnter={(e) =>
        ((e.currentTarget as HTMLDivElement).style.background = "var(--color-surface-hover)")
      }
      onMouseLeave={(e) =>
        ((e.currentTarget as HTMLDivElement).style.background = "transparent")
      }
    >
      <span
        style={{
          flex: 1,
          fontSize: "11px",
          color: "var(--color-text-muted)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {value}
      </span>
      <button
        onClick={onRemove}
        style={{
          width: "16px",
          height: "16px",
          border: "none",
          background: "transparent",
          color: "var(--color-text-muted)",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          padding: 0,
          borderRadius: "2px",
          transition: "color 0.1s",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-text-tertiary)")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-text-muted)")}
      >
        <svg width="7" height="7" viewBox="0 0 7 7" fill="none">
          <line x1="1" y1="1" x2="6" y2="6" stroke="currentColor" strokeWidth="1.5" />
          <line x1="6" y1="1" x2="1" y2="6" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      </button>
    </div>
  );
}
