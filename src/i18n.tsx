import { createContext, useContext, useCallback, ReactNode } from "react";

export type Lang = "ru" | "en";

const translations = {
  // BottomNav
  "nav.vpn": { ru: "VPN", en: "VPN" },
  "nav.routes": { ru: "Маршруты", en: "Routes" },
  "nav.logs": { ru: "Логи", en: "Logs" },
  "nav.settings": { ru: "Настройки", en: "Settings" },

  // VpnScreen
  "vpn.disconnected": { ru: "Отключено", en: "Disconnected" },
  "vpn.connected": { ru: "Подключено", en: "Connected" },
  "vpn.connecting": { ru: "Подключение...", en: "Connecting..." },
  "vpn.disconnecting": { ru: "Отключение...", en: "Disconnecting..." },
  "vpn.reconnecting": { ru: "Переподключение...", en: "Reconnecting..." },
  "vpn.servers": { ru: "Серверы", en: "Servers" },
  "vpn.paste": { ru: "+ Вставить", en: "+ Paste" },
  "vpn.paste_hint": { ru: "вставьте vless:// конфиг", en: "paste vless:// config" },
  "vpn.mode_proxy": { ru: "Прокси", en: "Proxy" },
  "vpn.mode_tun": { ru: "Туннель", en: "Tunnel" },

  // RoutesScreen
  "routes.sites": { ru: "Мимо VPN (сайты)", en: "Bypass VPN (sites)" },
  "routes.apps": { ru: "Мимо VPN (приложения)", en: "Bypass VPN (apps)" },
  "routes.empty": { ru: "пусто", en: "empty" },
  "routes.site_placeholder": { ru: "домен или IP/CIDR", en: "domain or IP/CIDR" },
  "routes.app_placeholder": { ru: "chrome.exe", en: "chrome.exe" },
  "routes.invalid_entry": { ru: "Неверный формат домена или IP", en: "Invalid domain or IP format" },

  // LogsScreen
  "logs.empty": { ru: "логов пока нет", en: "no logs yet" },

  // SettingsScreen
  "settings.general": { ru: "Основные", en: "General" },
  "settings.appearance": { ru: "Внешний вид", en: "Appearance" },
  "settings.autostart": { ru: "Автозапуск", en: "Autostart" },
  "settings.autostart_desc": { ru: "Запускать с Windows", en: "Launch with Windows" },
  "settings.language": { ru: "Язык", en: "Language" },
  "settings.auto_reconnect": { ru: "Автопереподключение", en: "Auto-reconnect" },
  "settings.auto_reconnect_desc": { ru: "При обрыве соединения", en: "On connection drop" },
  "settings.scale": { ru: "Масштаб", en: "Scale" },
  "settings.theme": { ru: "Тема", en: "Theme" },
  "settings.theme_dark": { ru: "Тёмная", en: "Dark" },
  "settings.theme_light": { ru: "Светлая", en: "Light" },

  // Tray
  "tray.show": { ru: "Показать", en: "Show" },
  "tray.quit": { ru: "Выход", en: "Quit" },
} as const;

type Key = keyof typeof translations;

interface I18nContextType {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: Key) => string;
}

const I18nContext = createContext<I18nContextType>(null!);

export function I18nProvider({ lang, setLang, children }: { lang: Lang; setLang: (l: Lang) => void; children: ReactNode }) {
  const t = useCallback((key: Key) => translations[key]?.[lang] ?? key, [lang]);

  return (
    <I18nContext.Provider value={{ lang, setLang, t }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useT() {
  const ctx = useContext(I18nContext);
  return ctx.t;
}

export function useI18n() {
  return useContext(I18nContext);
}
