import { useState, useEffect, useRef } from "react";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import { load as loadStore, Store } from "@tauri-apps/plugin-store";
import { Titlebar } from "./components/Titlebar";
import { VpnScreen } from "./components/VpnScreen";
import { RoutesScreen } from "./components/RoutesScreen";
import { LogsScreen } from "./components/LogsScreen";
import { SettingsScreen } from "./components/SettingsScreen";
import { BottomNav, Tab } from "./components/BottomNav";
import { I18nProvider, Lang } from "./i18n";

const STORE_FILE = "vpn.json";
const BASE_W = 480;
const BASE_H = 300;

function App() {
  const [tab, setTab] = useState<Tab>("vpn");
  const [connected, setConnected] = useState(false);
  const [logLines, setLogLines] = useState<string[]>([]);

  // Settings state
  const [lang, setLang] = useState<Lang>("ru");
  const [autostart, setAutostart] = useState(false);
  const [autoReconnect, setAutoReconnect] = useState(false);
  const [uiScale, setUiScale] = useState<100 | 125 | 150>(100);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [ready, setReady] = useState(false);
  const storeRef = useRef<Store | null>(null);

  // Load settings
  useEffect(() => {
    loadStore(STORE_FILE, { autoSave: false, defaults: {} }).then(async (store) => {
      storeRef.current = store;
      setLang((await store.get<Lang>("language")) ?? "ru");
      setAutostart((await store.get<boolean>("autostart")) ?? false);
      setAutoReconnect((await store.get<boolean>("auto_reconnect")) ?? false);

      let scale = await store.get<100 | 125 | 150>("ui_scale");
      if (!scale) {
        // Auto-detect on first launch
        const factor = await getCurrentWindow().scaleFactor();
        if (factor >= 1.5) scale = 150;
        else if (factor >= 1.25) scale = 125;
        else scale = 100;
      }
      setUiScale(scale);
      setTheme((await store.get<"dark" | "light">("theme")) ?? "dark");
      setReady(true);
    });
  }, []);

  // Save settings on change
  useEffect(() => {
    if (!ready || !storeRef.current) return;
    const store = storeRef.current;
    (async () => {
      await store.set("language", lang);
      await store.set("autostart", autostart);
      await store.set("auto_reconnect", autoReconnect);
      await store.set("ui_scale", uiScale);
      await store.set("theme", theme);
      await store.save();
    })();
  }, [lang, autostart, autoReconnect, uiScale, theme, ready]);

  // Apply theme
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  // Update tray labels on language change
  useEffect(() => {
    if (!ready) return;
    const showLabel = lang === "ru" ? "Показать" : "Show";
    const quitLabel = lang === "ru" ? "Выход" : "Quit";
    invoke("update_tray_labels", { showLabel, quitLabel }).catch(() => {});
  }, [lang, ready]);

  // Apply scale
  useEffect(() => {
    if (!ready) return;
    const zoom = uiScale / 100;
    document.documentElement.style.zoom = String(zoom);
    getCurrentWindow().setSize(
      new LogicalSize(Math.round(BASE_W * zoom), Math.round(BASE_H * zoom))
    );
  }, [uiScale, ready]);

  return (
    <I18nProvider lang={lang} setLang={setLang}>
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "var(--color-bg)",
          borderRadius: "var(--radius-lg)",
          overflow: "hidden",
        }}
      >
        <Titlebar connected={connected} showVersion={tab === "settings"} />
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ flex: 1, display: tab === "vpn" ? "flex" : "none", overflow: "hidden" }}>
            <VpnScreen
              connected={connected}
              setConnected={setConnected}
              setLogLines={setLogLines}
              autoReconnect={autoReconnect}
            />
          </div>
          <div style={{ flex: 1, display: tab === "routes" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
            <RoutesScreen />
          </div>
          <div style={{ flex: 1, display: tab === "logs" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
            <LogsScreen logLines={logLines} />
          </div>
          <div style={{ flex: 1, display: tab === "settings" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
            <SettingsScreen
              autostart={autostart}
              setAutostart={setAutostart}
              autoReconnect={autoReconnect}
              setAutoReconnect={setAutoReconnect}
              uiScale={uiScale}
              setUiScale={setUiScale}
              theme={theme}
              setTheme={setTheme}
            />
          </div>
        </div>
        <BottomNav active={tab} onChange={setTab} />
      </div>
    </I18nProvider>
  );
}

export default App;
