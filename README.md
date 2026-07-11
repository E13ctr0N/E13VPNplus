# E13VPN+

Windows VPN client for VLESS + Reality and NaiveProxy, including `xhttp` / `splithttp` support through Xray-core.

Built with Tauri v2, React, sing-box and Xray-core.

<p align="center">
  <img src="screenshots/vpn-connected.png" width="420" alt="VPN connected">
  <img src="screenshots/settings.png" width="420" alt="Settings">
</p>

## Difference From E13VPN

E13VPN+ is the extended version of the base [E13VPN](https://github.com/E13ctr0N/E13VPN) client.
It keeps the sing-box path for regular transports and NaiveProxy, and adds Xray-core for `xhttp` / `splithttp`.

Engine selection is automatic:

- `xhttp` / `splithttp` -> Xray-core.
- `tcp`, `ws`, `http`, `grpc`, `quic`, `httpupgrade` -> sing-box.
- `naive+https` / `naive+quic` -> sing-box NaiveProxy outbound.

Use E13VPN+ when the server uses `xhttp` / `splithttp`. Use the base E13VPN when those transports are not needed and a smaller package is preferable.

## Features

- Proxy mode: system HTTP proxy on a random local port.
- TUN mode: system traffic through a virtual WinTUN adapter.
- VLESS and NaiveProxy config storage with Windows DPAPI encryption.
- 3x-ui compatible subscription import for plain/Base64 URI lists.
- Domain/IP route bypass.
- Per-application bypass for sing-box transports and for Xray in TUN mode through the local sing-box router.
- Real-time speed indicator through sing-box Clash API.
- Auto-reconnect with backoff.
- Windows autostart.
- Tray icon status.
- Dark/light theme.
- Russian/English UI.
- Single-instance guard.

## Known Limits

- `bypass_apps` is not supported in Xray Proxy mode. Xray TUN mode uses a local sing-box router, so per-process bypass can work there.
- The speed indicator uses sing-box Clash API and is disabled for Xray connections.
- `Xray + TUN` uses Xray for `xhttp` / `splithttp` and a local sing-box TUN router for routes and DNS. The server bypass route currently requires an IPv4 server address.
- Subscription import stores the imported server links. The subscription URL itself is not stored or auto-refreshed yet; unsupported protocols such as `vmess`, `trojan`, `ss`, and `hysteria` are skipped.
- `wintun.dll` is required for TUN mode but is ignored by git. Download it with `scripts/get-wintun.ps1` before building from a clean clone.
- `libcronet.dll` is required for NaiveProxy outbound and is bundled from the official sing-box Windows archive.

## Build From Source

Requirements:

- Windows 10+.
- Node.js compatible with Vite 8 (`^20.19.0 || >=22.12.0`).
- Rust stable.
- Administrator rights for TUN mode runtime testing.

Install dependencies and build:

```bash
npm install
npm run tauri build
```

Download VPN engine binaries when preparing a clean checkout:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\get-engines.ps1
powershell -ExecutionPolicy Bypass -File scripts\get-wintun.ps1
```

`get-engines.ps1` downloads sing-box, `libcronet.dll`, and Xray-core into `src-tauri/binaries/` and prints SHA256 values.
After replacing binaries, update the matching SHA constants in `src-tauri/src/lib.rs`.

## Stack

| Component | Version |
| --- | --- |
| Tauri | 2.11 |
| React | 19.2.5 |
| Vite | 8.1.4 |
| TypeScript | 6.0.3 |
| Tailwind CSS | 4.2.4 |
| sing-box | 1.13.x |
| Xray-core | v26.3.27 |

## Verification

Useful local checks:

```bash
npm run build
npm audit --audit-level=moderate
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri build
```

## License

MIT
