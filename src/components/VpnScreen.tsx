import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { PowerButton } from "./PowerButton";
import { SpeedDisplay } from "./SpeedDisplay";
import { ModeSelector } from "./ModeSelector";
import { ConfigList, VlessConfig } from "./ConfigList";
import { useT } from "../i18n";
import { getVpnStore, queueVpnStoreSave } from "../store";

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
    if (uri.startsWith("naive+https://") || uri.startsWith("naive+quic://")) {
      return new URL(uri.replace(/^naive\+/, "")).hostname;
    }
  } catch {}
  try {
    return new URL(uri).hostname;
  } catch {}
  return "unnamed";
}

function isSupportedConfigUri(text: string): boolean {
  return (
    text.startsWith("vless://") ||
    text.startsWith("naive+https://") ||
    text.startsWith("naive+quic://")
  );
}

function isSubscriptionUrl(text: string): boolean {
  try {
    const url = new URL(text);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

interface VpnScreenProps {
  connected: boolean;
  setConnected: (v: boolean) => void;
  setLogLines: React.Dispatch<React.SetStateAction<string[]>>;
  autoReconnect?: boolean;
  autoConnectOnAutostart?: boolean;
  proxyUseSystemProxy: boolean;
  proxyRandomPort: boolean;
  proxyFixedPort: number;
}

type RoutePolicy = "bypass" | "only_vpn";

type ClashApiParams = {
  enabled: boolean;
  secret?: string;
  port?: number;
};

type ClashApiState = {
  enabled: boolean;
  secret: string;
  port: number;
};

type SubscriptionImportResult = {
  configs: string[];
  skipped: number;
};

export function VpnScreen({
  connected,
  setConnected,
  setLogLines,
  autoReconnect,
  autoConnectOnAutostart,
  proxyUseSystemProxy,
  proxyRandomPort,
  proxyFixedPort,
}: VpnScreenProps) {
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
  const [importStatus, setImportStatus] = useState("");
  const manualDisconnect = useRef(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempt = useRef(0);
  const connectTimeRef = useRef<number | null>(null);
  const configsRef = useRef(configs);
  const activeIdRef = useRef(activeId);
  const vpnModeRef = useRef(vpnMode);
  const autoStartAttempted = useRef(false);
  const proxyUseSystemProxyRef = useRef(proxyUseSystemProxy);
  const proxyRandomPortRef = useRef(proxyRandomPort);
  const proxyFixedPortRef = useRef(proxyFixedPort);
  configsRef.current = configs;
  activeIdRef.current = activeId;
  vpnModeRef.current = vpnMode;
  proxyUseSystemProxyRef.current = proxyUseSystemProxy;
  proxyRandomPortRef.current = proxyRandomPort;
  proxyFixedPortRef.current = proxyFixedPort;
  const MAX_RECONNECT_ATTEMPTS = 10;
  const clashApiRef = useRef<ClashApiState>({ enabled: false, secret: "", port: 9090 });

  async function startConfig(cfg: VlessConfig, source: "manual" | "auto-reconnect" | "auto-start") {
    const store = await getVpnStore();
    const bypassVpn = (await store.get<string[]>("routes_bypass")) ?? [];
    const bypassApps = (await store.get<string[]>("routes_bypass_apps")) ?? [];
    const routePolicy = (await store.get<RoutePolicy>("routes_policy")) ?? "bypass";
    if (source !== "manual") {
      setLogLines((prev) => [...prev, `[${source}] connecting...`]);
    }
    await invoke("start_vpn", {
      uri: cfg.uri,
      bypassVpn,
      bypassApps,
      mode: vpnModeRef.current,
      systemProxy: proxyUseSystemProxyRef.current,
      randomProxyPort: proxyRandomPortRef.current,
      fixedProxyPort: proxyFixedPortRef.current,
      routePolicy,
    });
    const now = Date.now();
    setConnected(true);
    setConnectTime(now);
    connectTimeRef.current = now;
    reconnectAttempt.current = 0;
    invoke("update_tray_icon", { connected: true }).catch(() => {});
  }

  function markDisconnected() {
    setConnected(false);
    setConnectTime(null);
    connectTimeRef.current = null;
    clashApiRef.current = { enabled: false, secret: "", port: 9090 };
    setSpeed(null);
    invoke("update_tray_icon", { connected: false }).catch(() => {});
  }

  // Listen for Clash API state from backend. Xray explicitly disables it.
  useEffect(() => {
    const unlisten = listen<ClashApiParams>("clash-api-params", (e) => {
      if (e.payload.enabled) {
        clashApiRef.current = {
          enabled: true,
          secret: e.payload.secret ?? "",
          port: e.payload.port ?? 9090,
        };
      } else {
        clashApiRef.current = { enabled: false, secret: "", port: 9090 };
        setSpeed(null);
      }
    });
    return () => { unlisten.then((f) => f()); };
  }, []);

  // Load store
  useEffect(() => {
    getVpnStore().then(async (store) => {
      // Try encrypted format first, fallback to legacy plaintext
      const storedEncrypted = await store.get<StoredConfig[]>("configs_encrypted");
      const legacyConfigs = await store.get<VlessConfig[]>("configs");
      let loadedConfigs: VlessConfig[] = [];
      if (storedEncrypted && storedEncrypted.length > 0) {
        loadedConfigs = await decryptConfigs(storedEncrypted);
      } else if (legacyConfigs && legacyConfigs.length > 0) {
        // Migrate: encrypt and save, then remove plaintext
        loadedConfigs = legacyConfigs;
        await queueVpnStoreSave(async (queuedStore) => {
          await queuedStore.set("configs_encrypted", await encryptConfigs(legacyConfigs));
          await queuedStore.delete("configs");
        });
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
    if (!clashApiRef.current.enabled) { setSpeed(null); return; }
    let cancelled = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    const controller = new AbortController();

    async function streamTraffic() {
      while (!cancelled) {
        try {
          const clashApi = clashApiRef.current;
          if (!clashApi.enabled) { setSpeed(null); return; }
          const headers: HeadersInit = clashApi.secret
            ? { "Authorization": `Bearer ${clashApi.secret}` }
            : {};
          const resp = await fetch(`http://127.0.0.1:${clashApi.port}/traffic`, { signal: controller.signal, headers });
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
    function scheduleReconnect() {
      if (!autoReconnect || manualDisconnect.current) return;
      const attempt = reconnectAttempt.current;
      if (attempt >= MAX_RECONNECT_ATTEMPTS) {
        setLogLines((prev) => [
          ...prev,
          `[auto-reconnect] gave up after ${MAX_RECONNECT_ATTEMPTS} attempts`,
        ]);
        reconnectAttempt.current = 0;
        setReconnecting(false);
        return;
      }

      const delay = Math.min(3000 * Math.pow(2, attempt), 60000);
      reconnectAttempt.current = attempt + 1;
      setReconnecting(true);
      setLogLines((prev) => [
        ...prev,
        `[auto-reconnect] attempt ${attempt + 1}/${MAX_RECONNECT_ATTEMPTS} in ${Math.round(delay / 1000)}s...`,
      ]);
      reconnectTimer.current = setTimeout(async () => {
        setReconnecting(false);
        if (manualDisconnect.current) return;
        const cfg = configsRef.current.find((c) => c.id === activeIdRef.current);
        if (!cfg) return;
        try {
          await startConfig(cfg, "auto-reconnect");
        } catch (err) {
          setLogLines((prev) => [...prev, `[auto-reconnect] failed: ${String(err)}`]);
          scheduleReconnect();
        }
      }, delay);
    }

    const unlistenLog = listen<string>("singbox-log", (e) => {
      setLogLines((prev) => {
        const next = [...prev, e.payload];
        return next.length > 200 ? next.slice(-200) : next;
      });
    });
    const unlistenTerm = listen<string>("singbox-terminated", (e) => {
      // Capture uptime before clearing connectTime
      const uptime = connectTimeRef.current ? Date.now() - connectTimeRef.current : 0;
      markDisconnected();
      setLogLines((prev) => [...prev, `[terminated] ${e.payload}`]);

      // Auto-reconnect with exponential backoff (3s, 6s, 12s... max 10 attempts)
      if (autoReconnect && !manualDisconnect.current) {
        // Only reset attempt counter if connection was stable (>10s uptime).
        // Prevents infinite reconnect loop when sing-box crashes immediately
        // (e.g. port conflict, wintun issue, antivirus kill).
        if (uptime > 10000) {
          reconnectAttempt.current = 0;
        }
        scheduleReconnect();
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
    if (!storeReady) return;
    void queueVpnStoreSave(async (store) => {
      await store.set("configs_encrypted", await encryptConfigs(configs));
      await store.set("activeId", activeId);
      await store.set("vpn_mode", vpnMode);
    }).catch((error) => {
      setLogLines((prev) => [...prev, `[store] save failed: ${String(error)}`]);
    });
  }, [configs, activeId, vpnMode, storeReady]);

  // Auto-connect only when the app was launched by the Windows autostart entry.
  useEffect(() => {
    if (!storeReady || !autoConnectOnAutostart || autoStartAttempted.current) return;
    if (connected || busy) return;
    const cfg = configs.find((c) => c.id === activeId);
    if (!cfg) return;

    autoStartAttempted.current = true;
    (async () => {
      const launchedFromAutostart = await invoke<boolean>("is_autostart_launch").catch(() => false);
      if (!launchedFromAutostart) return;
      setBusy("connecting");
      setLogLines([]);
      try {
        await startConfig(cfg, "auto-start");
      } catch (err) {
        setLogLines((prev) => [...prev, `[auto-start] failed: ${String(err)}`]);
      } finally {
        setBusy(false);
      }
    })();
  }, [storeReady, autoConnectOnAutostart, connected, busy, configs, activeId]);

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

  function appendConfigUris(uris: string[]): number {
    const seen = new Set(configsRef.current.map((cfg) => cfg.uri));
    const additions = uris
      .filter((uri) => !seen.has(uri))
      .map((uri) => {
        seen.add(uri);
        return { id: crypto.randomUUID(), name: parseConfigName(uri), uri };
      });

    if (additions.length === 0) return 0;

    setConfigs((prev) => {
      const current = new Set(prev.map((cfg) => cfg.uri));
      const unique = additions.filter((cfg) => !current.has(cfg.uri));
      return unique.length === 0 ? prev : [...prev, ...unique];
    });
    if (!activeIdRef.current) setActiveId(additions[0].id);
    return additions.length;
  }

  async function addFromClipboard() {
    if (!storeReady) {
      setImportStatus(t("vpn.store_loading"));
      return;
    }
    try {
      const text = (await readText()).trim();
      if (!text) {
        setImportStatus(t("vpn.clipboard_empty"));
        return;
      }

      if (isSupportedConfigUri(text)) {
        const added = appendConfigUris([text]);
        setImportStatus(added > 0 ? t("vpn.server_added") : t("vpn.server_exists"));
        setLogLines((prev) => [
          ...prev,
          added > 0 ? "[import] added 1 server" : "[import] server already exists",
        ]);
        return;
      }

      if (isSubscriptionUrl(text)) {
        setImportStatus(t("vpn.subscription_loading"));
        setLogLines((prev) => [...prev, "[subscription] downloading..."]);
        const result = await invoke<SubscriptionImportResult>("import_subscription_url", { url: text });
        const added = appendConfigUris(result.configs);
        const skipped = result.skipped > 0 ? `, skipped ${result.skipped}` : "";
        const message = result.configs.length > 0
          ? `[subscription] imported ${added}/${result.configs.length} servers${skipped}`
          : `[subscription] no supported servers found${skipped}`;
        setImportStatus(
          result.configs.length > 0
            ? `${t("vpn.subscription_imported")}: ${added}/${result.configs.length}`
            : t("vpn.subscription_empty")
        );
        setLogLines((prev) => [...prev, message]);
        return;
      }

      setImportStatus(t("vpn.clipboard_unsupported"));
      setLogLines((prev) => [...prev, "[import] unsupported clipboard format"]);
    } catch (err) {
      setImportStatus(`${t("vpn.import_failed")}: ${String(err)}`);
      setLogLines((prev) => [...prev, `[subscription] failed: ${String(err)}`]);
    }
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
        markDisconnected();
      } catch (e) {
        setLogLines((prev) => [...prev, `[error] stop_vpn failed: ${String(e)}`]);
      } finally {
        setBusy(false);
      }
      return;
    }

    if (busy) return; // disconnecting — не прерываем

    const cfg = configs.find((c) => c.id === activeId)!;
    try {
      if (!connected) {
        manualDisconnect.current = false;
        setBusy("connecting");
        setLogLines([]);
        await startConfig(cfg, "manual");
      } else {
        setBusy("disconnecting");
        manualDisconnect.current = true;
        if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
        setReconnecting(false);
        await invoke("stop_vpn");
        markDisconnected();
      }
    } catch (e) {
      if (!String(e).includes("connection cancelled")) {
        setLogLines((prev) => [...prev, `[error] ${String(e)}`]);
      }
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
          pasteDisabled={!storeReady}
          status={importStatus}
        />
      </div>
    </div>
  );
}
