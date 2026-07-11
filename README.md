# E13VPN+

VPN-клиент для Windows с поддержкой VLESS + Reality и NaiveProxy, включая транспорты `xhttp` / `splithttp` через Xray-core.

Построен на Tauri v2, React, sing-box и Xray-core.

<p align="center">
  <img src="screenshots/vpn-connected.png" width="420" alt="E13VPN+ — подключение установлено">
  <img src="screenshots/settings.png" width="420" alt="E13VPN+ — настройки">
</p>

## Отличия от E13VPN

E13VPN+ — расширенная версия базового клиента [E13VPN](https://github.com/E13ctr0N/E13VPN).
Обычные транспорты и NaiveProxy работают через sing-box, а для `xhttp` / `splithttp` используется Xray-core.

Движок выбирается автоматически:

- `xhttp` / `splithttp` → Xray-core;
- `tcp`, `ws`, `http`, `grpc`, `quic`, `httpupgrade` → sing-box;
- `naive+https` / `naive+quic` → NaiveProxy outbound в sing-box.

E13VPN+ стоит выбирать, если сервер использует `xhttp` / `splithttp` или NaiveProxy. Базовый E13VPN подойдёт, когда эти протоколы не нужны и важен меньший размер установщика.

## Возможности

- Proxy-режим: системный HTTP-прокси на случайном локальном порту.
- TUN-режим: системный трафик через виртуальный адаптер WinTUN.
- Поддержка VLESS + Reality и NaiveProxy (`naive+https`, `naive+quic`).
- Шифрование сохранённых конфигураций через Windows DPAPI.
- Импорт совместимых с 3x-ui подписок: обычные и Base64-списки URI.
- Обход VPN по доменам и IP-адресам.
- Обход VPN для отдельных приложений в sing-box и в Xray TUN через локальный sing-box router.
- Индикатор скорости в реальном времени через sing-box Clash API.
- Автоматическое переподключение с увеличивающейся задержкой.
- Автозапуск вместе с Windows.
- Иконка в трее с отображением статуса.
- Тёмная и светлая темы.
- Русский и английский интерфейс.
- Защита от запуска второго экземпляра.

## Известные ограничения

- `bypass_apps` не поддерживается в Xray Proxy. В Xray TUN обход по приложениям работает через локальный sing-box router.
- Индикатор скорости использует sing-box Clash API и отключён при прямом подключении через Xray.
- В режиме `Xray + TUN` транспорт `xhttp` / `splithttp` обслуживает Xray, а маршруты и DNS — локальный sing-box TUN router. Для маршрута обхода сервера сейчас требуется его IPv4-адрес.
- При импорте подписки сохраняются ссылки на серверы. URL самой подписки пока не сохраняется и автоматически не обновляется. Неподдерживаемые протоколы (`vmess`, `trojan`, `ss`, `hysteria`) пропускаются.
- Для TUN необходим `wintun.dll`, который не хранится в Git. Перед сборкой из чистого клона загрузите его через `scripts/get-wintun.ps1`.
- Для NaiveProxy необходим `libcronet.dll`; скрипт сборки загружает его из официального Windows-архива sing-box.
- UDP через NaiveProxy в TUN по умолчанию блокируется. Для серверов с поддержкой UDP over TCP его можно явно включить параметром `uot=1` в URI.

## Сборка из исходников

Требования:

- Windows 10 или новее;
- Node.js, совместимый с Vite 8 (`^20.19.0 || >=22.12.0`);
- стабильная версия Rust;
- права администратора для запуска и проверки TUN-режима.

Установите зависимости и соберите приложение:

```bash
npm install
npm run tauri build
```

Для сборки из чистого клона загрузите VPN-движки и WinTUN:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\get-engines.ps1
powershell -ExecutionPolicy Bypass -File scripts\get-wintun.ps1
```

`get-engines.ps1` загружает sing-box, `libcronet.dll` и Xray-core в `src-tauri/binaries/`, а затем выводит их SHA256.
После замены бинарных файлов обновите соответствующие SHA-константы в `src-tauri/src/lib.rs`.

## Технологии

| Компонент | Версия |
| --- | --- |
| Tauri | 2.11 |
| React | 19.2.5 |
| Vite | 8.1.4 |
| TypeScript | 6.0.3 |
| Tailwind CSS | 4.2.4 |
| sing-box | 1.13.x |
| Xray-core | v26.3.27 |

## Проверка

Основные локальные проверки:

```bash
npm run build
npm audit --audit-level=moderate
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri build
```

## Лицензия

MIT
