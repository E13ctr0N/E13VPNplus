import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { load as loadStore, Store } from "@tauri-apps/plugin-store";
import { PowerButton } from "./PowerButton";
import { SpeedDisplay } from "./SpeedDisplay";
import { ModeSelector } from "./ModeSelector";
import { ConfigList, VlessConfig } from "./ConfigList";
import { useT } from "../i18n";

const STORE_FILE = "vpn.json";

interface StoredConfig {
  id: string;
  name: string;
  uri_encrypted: string;
}

async function encryptConfigs(configs: VlessConfig[]): Promise<StoredConfig[]> {
  return Promise.all(configs.map(async (c) => ({
    id: c.id,
    name: c.name,
    uri_encrypted: await invoke<string>("encrypt_string", { value: c.uri }),
  })));
}

async function decryptConfigs(stored: StoredConfig[]): Promise<VlessConfig[]> {
  return Promise.all(stored.map(async (c) => ({
    id: c.id,
    name: c.name,
    uri: await invoke<string>("decrypt_string", { value: c.uri_encrypted }),
  })));
}

function parseConfigName(uri: string): string {
  try {
    const fragment = new URL(uri).hash.slice(1);
    if (fragment) return decodeURIComponent(fragment);
  } catch {}
  try {
    return new URL(uri).hostname;
  } catch {}
  return "unnamed";
}

interface VpnScreenProps {
  connected: boolean;
  setConnected: (v: boolean) => void;
  setLogLines: React.Dispatch<React.SetStateAction<string[]>>;
  autoReconnect?: boolean;
}

export function VpnScreen({ connected, setConnected, setLogLines, autoReconnect }: VpnScreenProps) {
  const t = useT();
  const [configs, setConfigs] = useState<VlessConfig[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [busy, setBusy] = useState<false | "connecting" | "disconnecting">(false);
  const [storeReady, setStoreReady] = useState(false);
  const [vpnMode, setVpnMode] = useState<"proxy" | "tun">("proxy");
  const [speed, setSpeed] = useState<{ down: number; up: number } | null>(null);
  const [connectTime, setConnectTime] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState("—");
  const [reconnecting, setReconnecting] = useState(false);
  const storeRef = useRef<Store | null>(null);
  const manualDisconnect = useRef(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempt = useRef(0);
  const connectTimeRef = useRef<number | null>(null);
  const configsRef = useRef(configs);
  const activeIdRef = useRef(activeId);
  const vpnModeRef = useRef(vpnMode);
  configsRef.current = configs;
  activeIdRef.current = activeId;
  vpnModeRef.current = vpnMode;
  const MAX_RECONNECT_ATTEMPTS = 10;
  const clashSecretRef = useRef("");

  // Listen for clash API params (secret + port) from backend
  useEffect(() => {
    const unlisten = listen<{ secret: string; port: number }>("clash-api-params", (e) => {
      clashSecretRef.current = e.payload.secret;
    });
    return () => { unlisten.then((f) => f()); };
  }, []);

  // Load store
  useEffect(() => {
    loadStore(STORE_FILE, { autoSave: false, defaults: {} }).then(async (store) => {
      storeRef.current = store;
      // Try encrypted format first, fallback to legacy plaintext
      const storedEncrypted = await store.get<StoredConfig[]>("configs_encrypted");
      const legacyConfigs = await store.get<VlessConfig[]>("configs");
      let loadedConfigs: VlessConfig[] = [];
      if (storedEncrypted && storedEncrypted.length > 0) {
        loadedConfigs = await decryptConfigs(storedEncrypted);
      } else if (legacyConfigs && legacyConfigs.length > 0) {
        // Migrate: encrypt and save, then remove plaintext
        loadedConfigs = legacyConfigs;
        await store.set("configs_encrypted", await encryptConfigs(legacyConfigs));
        await store.delete("configs");
        await store.save();
      }
      const savedActiveId = (await store.get<string>("activeId")) ?? null;
      const savedMode = (await store.get<"proxy" | "tun">("vpn_mode")) ?? "proxy";
      setConfigs(loadedConfigs);
      setActiveId(savedActiveId);
      setVpnMode(savedMode);
      setStoreReady(true);
    }).catch((err) => {
      console.error("Failed to load store:", err);
      setStoreReady(true); // Allow app to function with empty configs
    });
  }, []);

  // Traffic streaming
  useEffect(() => {
    if (!connected) { setSpeed(null); return; }
    let cancelled = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    const controller = new AbortController();

    async function streamTraffic() {
      while (!cancelled) {
        try {
          const headers: HeadersInit = clashSecretRef.current
            ? { "Authorization": `Bearer ${clashSecretRef.current}` }
            : {};
          const resp = await fetch("http://127.0.0.1:9090/traffic", { signal: controller.signal, headers });
          const body = resp.body;
          if (!body) continue;
          reader = body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          while (!cancelled) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() ?? "";
            for (const line of lines) {
              if (!line.trim()) continue;
              try {
                const data = JSON.parse(line);
                setSpeed({ down: data.down ?? 0, up: data.up ?? 0 });
              } catch {}
            }
          }
        } catch {}
        if (!cancelled) await new Promise((r) => setTimeout(r, 2000));
      }
    }
    streamTraffic();
    return () => { cancelled = true; controller.abort(); reader?.cancel().catch(() => {}); };
  }, [connected]);

  // Sing-box events
  useEffect(() => {
    const unlistenLog = listen<string>("singbox-log", (e) => {
      setLogLines((prev) => {
        const next = [...prev, e.payload];
        return next.length > 200 ? next.slice(-200) : next;
      });
    });
    const unlistenTerm = listen<string>("singbox-terminated", (e) => {
      // Capture uptime before clearing connectTime
      const uptime = connectTimeRef.current ? Date.now() - connectTimeRef.current : 0;
      setConnected(false);
      setConnectTime(null);
      connectTimeRef.current = null;
      invoke("update_tray_icon", { connected: false }).catch(() => {});
      setLogLines((prev) => [...prev, `[terminated] ${e.payload}`]);

      // Auto-reconnect with exponential backoff (3s, 6s, 12s... max 10 attempts)
      if (autoReconnect && !manualDisconnect.current) {
        // Only reset attempt counter if connection was stable (>10s uptime).
        // Prevents infinite reconnect loop when sing-box crashes immediately
        // (e.g. port conflict, wintun issue, antivirus kill).
        if (uptime > 10000) {
          reconnectAttempt.current = 0;
        }
        const attempt = reconnectAttempt.current;
        if (attempt >= MAX_RECONNECT_ATTEMPTS) {
          setLogLines((prev) => [...prev, `[auto-reconnect] gave up after ${MAX_RECONNECT_ATTEMPTS} attempts`]);
          reconnectAttempt.current = 0;
        } else {
          const delay = Math.min(3000 * Math.pow(2, attempt), 60000); // 3s, 6s, 12s, 24s, 48s, 60s max
          reconnectAttempt.current = attempt + 1;
          setReconnecting(true);
          setLogLines((prev) => [...prev, `[auto-reconnect] attempt ${attempt + 1}/${MAX_RECONNECT_ATTEMPTS} in ${Math.round(delay / 1000)}s...`]);
          reconnectTimer.current = setTimeout(() => {
            setReconnecting(false);
            const doReconnect = async () => {
              const cfg = configsRef.current.find((c) => c.id === activeIdRef.current);
              if (!cfg) return;
              const store = storeRef.current ?? await loadStore(STORE_FILE, { autoSave: false, defaults: {} });
              const bypassVpn = (await store.get<string[]>("routes_bypass")) ?? [];
              const bypassApps = (await store.get<string[]>("routes_bypass_apps")) ?? [];
              try {
                setLogLines((prev) => [...prev, "[auto-reconnect] connecting..."]);
                await invoke("start_vpn", { uri: cfg.uri, bypassVpn, bypassApps, mode: vpnModeRef.current });
                const now = Date.now();
                setConnected(true);
                setConnectTime(now);
                connectTimeRef.current = now;
                invoke("update_tray_icon", { connected: true }).catch(() => {});
              } catch (err) {
                setLogLines((prev) => [...prev, `[auto-reconnect] failed: ${String(err)}`]);
              }
            };
            doReconnect();
          }, delay);
        }
      }
      manualDisconnect.current = false;
    });
    return () => {
      unlistenLog.then((f) => f());
      unlistenTerm.then((f) => f());
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [setConnected, setLogLines, autoReconnect]);

  // Save on change
  useEffect(() => {
    if (!storeReady || !storeRef.current) return;
    const store = storeRef.current;
    (async () => {
      await store.set("configs_encrypted", await encryptConfigs(configs));
      await store.set("activeId", activeId);
      await store.set("vpn_mode", vpnMode);
      await store.save();
    })();
  }, [configs, activeId, vpnMode, storeReady]);

  // Timer
  useEffect(() => {
    if (!connectTime) { setElapsed("—"); return; }
    const interval = setInterval(() => {
      const sec = Math.floor((Date.now() - connectTime) / 1000);
      const m = String(Math.floor(sec / 60)).padStart(2, "0");
      const s = String(sec % 60).padStart(2, "0");
      setElapsed(`${m}:${s}`);
    }, 1000);
    return () => clearInterval(interval);
  }, [connectTime]);

  async function addFromClipboard() {
    try {
      const text = (await readText()).trim();
      if (!text.startsWith("vless://")) return;
      const id = crypto.randomUUID();
      const name = parseConfigName(text);
      setConfigs((prev) => [...prev, { id, name, uri: text }]);
      if (!activeId) setActiveId(id);
    } catch {}
  }

  function removeConfig(id: string) {
    if (connected && id === activeId) return;
    setConfigs((prev) => prev.filter((c) => c.id !== id));
    if (activeId === id) setActiveId(null);
  }

  async function toggleConnect() {
    if (!activeId) return;

    // Если идёт подключение — отменяем (stop_vpn убьёт процесс)
    if (busy === "connecting") {
      manualDisconnect.current = true;
      setBusy("disconnecting");
      try {
        await invoke("stop_vpn");
      } catch {}
      setConnected(false);
      setConnectTime(null);
      connectTimeRef.current = null;
      invoke("update_tray_icon", { connected: false }).catch(() => {});
      setBusy(false);
      return;
    }

    if (busy) return; // disconnecting — не прерываем

    const cfg = configs.find((c) => c.id === activeId)!;
    try {
      if (!connected) {
        setBusy("connecting");
        setLogLines([]);
        const store = storeRef.current ?? await loadStore(STORE_FILE, { autoSave: false, defaults: {} });
        const bypassVpn = (await store.get<string[]>("routes_bypass")) ?? [];
        const bypassApps = (await store.get<string[]>("routes_bypass_apps")) ?? [];
        await invoke("start_vpn", { uri: cfg.uri, bypassVpn, bypassApps, mode: vpnMode });
        const now = Date.now();
        setConnected(true);
        setConnectTime(now);
        connectTimeRef.current = now;
        reconnectAttempt.current = 0;
        invoke("update_tray_icon", { connected: true }).catch(() => {});
      } else {
        setBusy("disconnecting");
        manualDisconnect.current = true;
        if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
        setReconnecting(false);
        await invoke("stop_vpn");
        setConnected(false);
        setConnectTime(null);
        connectTimeRef.current = null;
        invoke("update_tray_icon", { connected: false }).catch(() => {});
      }
    } catch (e) {
      setLogLines((prev) => [...prev, `[error] ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  }

  const powerState = busy || reconnecting ? "connecting" : connected ? "on" : "off";
  const statusText = reconnecting
    ? t("vpn.reconnecting")
    : busy === "disconnecting"
    ? t("vpn.disconnecting")
    : busy === "connecting"
    ? t("vpn.connecting")
    : connected
    ? t("vpn.connected")
    : t("vpn.disconnected");
  const statusColor = busy || reconnecting
    ? "var(--color-text-tertiary)"
    : connected
    ? "var(--color-text-secondary)"
    : "var(--color-text-muted)";

  return (
    <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
      {/* Left panel */}
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "12px",
          padding: "16px",
        }}
      >
        <PowerButton state={powerState} onClick={toggleConnect} disabled={!activeId || busy === "disconnecting"} />
        <span style={{ fontSize: "11px", fontWeight: 500, color: statusColor, transition: "color 0.3s" }}>
          {statusText}
        </span>
        <span
          style={{
            fontSize: "9px",
            color: connected ? "var(--color-text-muted)" : "var(--color-text-ghost)",
            transition: "color 0.3s",
          }}
        >
          {elapsed}
        </span>
        <SpeedDisplay speed={speed} active={connected} />
        <ModeSelector mode={vpnMode} onChange={setVpnMode} disabled={connected || !!busy} />
      </div>

      {/* Divider */}
      <div style={{ width: "1px", background: "var(--color-border)", flexShrink: 0 }} />

      {/* Right panel */}
      <div style={{ flex: 1.1, display: "flex", flexDirection: "column", padding: "14px", overflow: "hidden" }}>
        <ConfigList
          configs={configs}
          activeId={activeId}
          connected={connected}
          onSelect={setActiveId}
          onRemove={removeConfig}
          onPaste={addFromClipboard}
        />
      </div>
    </div>
  );
}
