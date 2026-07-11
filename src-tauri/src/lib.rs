mod subscription;
mod vpn;
mod vpn_xray;

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

static SYSTEM_PROXY_OWNED: AtomicBool = AtomicBool::new(false);

/// Убирает нативную рамку DWM и стили окна (borderless transparent window)
#[cfg(windows)]
fn apply_dwm_borderless(hwnd: windows_sys::Win32::Foundation::HWND) {
    use windows_sys::Win32::Graphics::Dwm::{
        DwmExtendFrameIntoClientArea, DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE,
        DWMWCP_ROUND,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, GWL_STYLE, SWP_FRAMECHANGED,
        SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, WS_BORDER, WS_CAPTION, WS_THICKFRAME,
    };

    unsafe {
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        SetWindowLongPtrW(
            hwnd,
            GWL_STYLE,
            style & !(WS_CAPTION as isize) & !(WS_THICKFRAME as isize) & !(WS_BORDER as isize),
        );
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
        );
        // IMPORTANT: -1 margins cause a white top border on Win10!
        let margins = windows_sys::Win32::UI::Controls::MARGINS {
            cxLeftWidth: 0,
            cxRightWidth: 0,
            cyTopHeight: 0,
            cyBottomHeight: 0,
        };
        DwmExtendFrameIntoClientArea(hwnd, &margins);
        let preference = DWMWCP_ROUND;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &preference as *const _ as *const _,
            std::mem::size_of_val(&preference) as u32,
        );
    }
}

#[cfg(windows)]
unsafe extern "system" fn borderless_subclass_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
    _uid_subclass: usize,
    _ref_data: usize,
) -> isize {
    const WM_NCACTIVATE: u32 = 0x0086;
    const WM_NCPAINT: u32 = 0x0085;
    match msg {
        WM_NCACTIVATE => return 1,
        WM_NCPAINT => return 0,
        _ => {}
    }
    windows_sys::Win32::UI::Shell::DefSubclassProc(hwnd, msg, wparam, lparam)
}

#[cfg(windows)]
fn install_borderless_subclass(hwnd: windows_sys::Win32::Foundation::HWND) {
    unsafe {
        windows_sys::Win32::UI::Shell::SetWindowSubclass(
            hwnd,
            Some(borderless_subclass_proc),
            1,
            0,
        );
    }
}

const EXPECTED_SINGBOX_SHA256: &str =
    "6325205ff2dd0a3046edbad492714621a4f5af80a0a18c915a5976fa07e9c377";
const EXPECTED_LIBCRONET_SHA256: &str =
    "8ef1f8bbde77f954af1ae47bee1819ac8dc2354bb0e1d4baba3dad9e58d7a6f7";
const EXPECTED_WINTUN_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

// Xray-core v26.3.27 (downloaded via scripts/get-xray.ps1)
const EXPECTED_XRAY_SHA256: &str =
    "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1";

const XRAY_BINARY_NAME: &str = "xray-x86_64-pc-windows-msvc.exe";
const TUN2SOCKS_BINARY_NAME: &str = "tun2socks-x86_64-pc-windows-msvc.exe";
const SINGBOX_BINARY_NAME: &str = "sing-box-x86_64-pc-windows-msvc.exe";
const LIBCRONET_BINARY_NAME: &str = "libcronet.dll";

#[derive(Debug, Clone, Copy)]
struct OwnedBypassRoute {
    server_ip: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
}

struct VpnState {
    process: Mutex<Option<CommandChild>>,
    /// Helper process for Xray+TUN: sing-box owns TUN/routing and forwards proxy traffic to Xray SOCKS.
    process_helper: Mutex<Option<CommandChild>>,
    pid: Mutex<Option<u32>>,
    pid_helper: Mutex<Option<u32>>,
    engine: Mutex<vpn::VpnEngine>,
    mode: Mutex<vpn::VpnMode>,
    proxy_port: Mutex<u16>,
    clash_secret: Mutex<String>,
    last_tun_stop: Mutex<Option<Instant>>,
    operation_lock: tokio::sync::Mutex<()>,
    session_generation: AtomicU64,
    ready_session: AtomicU64,
    /// IP сервера для которого добавлен bypass-route через real gateway (Xray+TUN).
    /// None если маршрут не добавлялся.
    bypass_route_ip: Mutex<Option<OwnedBypassRoute>>,
}

const DYNAMIC_PORT_START: u16 = 49152;
const PROXY_PORT_MAX: u16 = 65534;
const FIXED_PROXY_PORT_DEFAULT: u16 = 2080;
const FIXED_PROXY_PORT_MIN: u16 = 1024;

fn port_from_hash(hash: u64) -> u16 {
    DYNAMIC_PORT_START + (hash % u64::from(PROXY_PORT_MAX - DYNAMIC_PORT_START + 1)) as u16
}

fn random_port() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    // Keep 65535 free for Xray SOCKS inbound at proxy_port + 1.
    port_from_hash(h.finish())
}

fn fixed_proxy_port(port: Option<u16>) -> Result<u16, String> {
    let port = port.unwrap_or(FIXED_PROXY_PORT_DEFAULT);
    if !(FIXED_PROXY_PORT_MIN..=PROXY_PORT_MAX).contains(&port) {
        return Err(format!(
            "Fixed proxy port must be between {FIXED_PROXY_PORT_MIN} and {PROXY_PORT_MAX}"
        ));
    }
    Ok(port)
}

fn selected_proxy_port(random_proxy_port: bool, fixed_port: Option<u16>) -> Result<u16, String> {
    if random_proxy_port {
        Ok(random_port())
    } else {
        fixed_proxy_port(fixed_port)
    }
}

fn ensure_tcp_loopback_port_free(port: u16) -> Result<(), String> {
    std::net::TcpListener::bind(("127.0.0.1", port))
        .map(|_| ())
        .map_err(|e| format!("127.0.0.1:{port} is not available: {e}"))
}

fn ensure_fixed_proxy_ports_available(
    engine: &vpn::VpnEngine,
    mode: &vpn::VpnMode,
    proxy_port: u16,
) -> Result<(), String> {
    match (engine, mode) {
        (vpn::VpnEngine::SingBox, vpn::VpnMode::Proxy) => {
            ensure_tcp_loopback_port_free(proxy_port)?;
        }
        (vpn::VpnEngine::Xray, _) => {
            ensure_tcp_loopback_port_free(proxy_port)?;
            ensure_tcp_loopback_port_free(proxy_port.saturating_add(1))?;
        }
        _ => {}
    }
    Ok(())
}

fn mark_system_proxy_owned(port: u16) -> Result<(), String> {
    vpn::acquire_system_proxy(port)?;
    SYSTEM_PROXY_OWNED.store(true, Ordering::SeqCst);
    Ok(())
}

fn clear_owned_system_proxy(_port: u16) {
    if SYSTEM_PROXY_OWNED.swap(false, Ordering::SeqCst) {
        let _ = vpn::release_system_proxy();
    }
}

fn random_secret() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    format!("{:016x}", h.finish())
}

const TUN_INTERFACE_NAME: &str = "E13VPN";

/// Remove stale WinTUN adapter left after crash/force-kill.
/// Without this, sing-box fails with "file already exists" on next TUN start.
fn cleanup_stale_tun_adapter() {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let script = format!(
            r#"Get-PnpDevice -Class Net -Status Error,Unknown -EA SilentlyContinue |
               Where-Object {{ $_.FriendlyName -match '{}|sing-tun|wintun' }} |
               ForEach-Object {{ pnputil /remove-device $_.InstanceId }}"#,
            TUN_INTERFACE_NAME
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .creation_flags(0x08000000)
            .output();
        // Also try removing by interface name (covers non-phantom adapters)
        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                "set",
                "interface",
                TUN_INTERFACE_NAME,
                "admin=disable",
            ])
            .creation_flags(0x08000000)
            .output();
    }
}

fn kill_orphan_by_name(image_name: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", image_name])
            .creation_flags(0x08000000)
            .output();
        std::thread::sleep(Duration::from_millis(500));
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", image_name])
            .creation_flags(0x08000000)
            .output();
    }
    #[cfg(not(windows))]
    {
        let _ = image_name;
    }
}

#[allow(dead_code)]
fn kill_orphan_tun2socks() {
    kill_orphan_by_name(TUN2SOCKS_BINARY_NAME);
}

/// Убить все возможные VPN-процессы любого ядра. Используется в panic-hook
/// и при startup-cleanup, когда мы не знаем, что могло остаться после краша.
fn kill_orphan_all() {
    kill_orphan_by_name(TUN2SOCKS_BINARY_NAME); // tun2socks первым — снимает TUN
    kill_orphan_by_name(XRAY_BINARY_NAME);
    kill_orphan_by_name(SINGBOX_BINARY_NAME);
}

fn graceful_kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .creation_flags(0x08000000)
            .output();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(200));
            let check = std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .creation_flags(0x08000000)
                .output();
            if let Ok(out) = check {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // tasklist выводит "INFO: No tasks are running..." если процесс уже завершён.
                // Универсальная проверка: искать PID в строке (работает для любого ядра).
                if stdout.contains("No tasks") || !stdout.contains(&pid.to_string()) {
                    return;
                }
            }
        }
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .creation_flags(0x08000000)
            .output();
    }
}

fn verify_binary_sha256(path: &std::path::Path, expected: &str, label: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    // Режим разработки: TODO-плейсхолдеры отключают проверку, но логируют предупреждение.
    // В production EXPECTED_*_SHA256 должен быть реальным хешем.
    if expected.starts_with("TODO_") {
        eprintln!("[warn] {label} SHA256 check skipped (placeholder in EXPECTED_*_SHA256 const)");
        return Ok(());
    }
    let data = std::fs::read(path).map_err(|e| format!("{label} binary read error: {e}"))?;
    let hash = format!("{:x}", Sha256::digest(&data));
    if hash != expected {
        return Err(format!(
            "{label} integrity check failed: expected {}, got {}",
            expected, hash
        ));
    }
    Ok(())
}

fn verify_singbox_binary(path: &std::path::Path) -> Result<(), String> {
    verify_binary_sha256(path, EXPECTED_SINGBOX_SHA256, "sing-box")
}

fn verify_xray_binary(path: &std::path::Path) -> Result<(), String> {
    verify_binary_sha256(path, EXPECTED_XRAY_SHA256, "xray")
}

fn refresh_verified_runtime_file(
    source: &std::path::Path,
    destination: &std::path::Path,
    expected_hash: &str,
    label: &str,
) -> Result<(), String> {
    verify_binary_sha256(source, expected_hash, label)?;
    if source == destination {
        return Ok(());
    }

    let temp = destination.with_extension("e13tmp");
    let _ = std::fs::remove_file(&temp);
    std::fs::copy(source, &temp).map_err(|e| format!("copy {label} to runtime temp: {e}"))?;
    verify_binary_sha256(&temp, expected_hash, label).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })?;
    if destination.exists() {
        std::fs::remove_file(destination)
            .map_err(|e| format!("replace existing runtime {label}: {e}"))?;
    }
    std::fs::rename(&temp, destination).map_err(|e| format!("activate runtime {label}: {e}"))?;
    verify_binary_sha256(destination, expected_hash, label)
}

fn cleanup_runtime_config_files(data_dir: &std::path::Path) {
    for filename in ["singbox.json", "xray.json", "xray-singbox-router.json"] {
        let _ = std::fs::remove_file(data_dir.join(filename));
    }
}

fn remove_loaded_runtime_config(app: &AppHandle, path: &std::path::Path) {
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            let _ = app.emit(
                "singbox-log",
                format!("[warn] runtime config cleanup failed: {error}"),
            );
        }
    }
}

#[cfg(windows)]
fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = windows_sys::Win32::Foundation::CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

fn ensure_current_session(state: &VpnState, session_id: u64) -> Result<(), String> {
    if state.session_generation.load(Ordering::SeqCst) != session_id {
        cleanup_vpn(state);
        return Err("connection cancelled".into());
    }
    Ok(())
}

fn cleanup_vpn(state: &VpnState) {
    state.ready_session.store(0, Ordering::SeqCst);
    // Stop helper first so TUN routes go away before the primary core exits.
    let helper_pid = state
        .pid_helper
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    let _ = state
        .process_helper
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(pid) = helper_pid {
        graceful_kill_pid(pid);
    }

    let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
    let _ = state
        .process
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(pid) = pid {
        graceful_kill_pid(pid);
    }

    let port = *state.proxy_port.lock().unwrap_or_else(|e| e.into_inner());
    clear_owned_system_proxy(port);
    let mode = state.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if mode == vpn::VpnMode::Tun {
        cleanup_stale_tun_adapter();
    }

    // Снять bypass-route если он был добавлен (Xray+TUN режим).
    let bypass_ip = state
        .bypass_route_ip
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(route) = bypass_ip {
        let _ = remove_server_bypass_route(route);
    }
}

/// Результат попытки запуска VPN-ядра
enum StartOutcome {
    /// Ядро стартовало и готово
    Ready,
    /// Процесс сам завершился (wintun race / ошибка конфига) — kill не нужен
    Crashed(String),
    /// Таймаут — процесс завис, был убит
    Timeout,
}

/// Контекст запуска одного ядра (sing-box или xray) в primary slot состояния.
struct PrimaryEngineCtx<'a> {
    engine: &'a vpn::VpnEngine,
    config_str: &'a str,
    data_dir: &'a std::path::Path,
    vpn_mode: &'a vpn::VpnMode,
    timeout_secs: u64,
    /// Порт для system proxy (Proxy mode); для TUN не используется.
    proxy_port: u16,
    system_proxy: bool,
    requires_libcronet: bool,
}

impl<'a> PrimaryEngineCtx<'a> {
    fn sidecar_name(&self) -> &'static str {
        match self.engine {
            vpn::VpnEngine::SingBox => "sing-box",
            vpn::VpnEngine::Xray => "xray",
        }
    }

    fn log_prefix(&self) -> &'static str {
        match self.engine {
            vpn::VpnEngine::SingBox => "",
            vpn::VpnEngine::Xray => "[xray] ",
        }
    }

    /// В TUN-режиме sing-box сам поднимает туннель; для Xray туннель поднимает
    /// tun2socks отдельно, поэтому current_dir (где лежит wintun.dll) нужен
    /// только sing-box'у.
    fn needs_data_cwd(&self) -> bool {
        (matches!(self.engine, vpn::VpnEngine::SingBox) && *self.vpn_mode == vpn::VpnMode::Tun)
            || self.requires_libcronet
    }

    /// В TUN-режиме с Xray system proxy НЕ ставится — маршрутизация идёт через tun2socks.
    fn should_set_system_proxy(&self) -> bool {
        self.system_proxy && *self.vpn_mode == vpn::VpnMode::Proxy
    }
}

/// Одна попытка запуска primary VPN-ядра (sing-box или xray).
async fn attempt_start_engine(
    app: &AppHandle,
    state: &State<'_, VpnState>,
    ctx: &PrimaryEngineCtx<'_>,
    session_id: u64,
) -> StartOutcome {
    let mut cmd = match app.shell().sidecar(ctx.sidecar_name()) {
        Ok(c) => c.args(["run", "-c", ctx.config_str]),
        Err(e) => return StartOutcome::Crashed(e.to_string()),
    };
    if ctx.needs_data_cwd() {
        cmd = cmd.current_dir(ctx.data_dir);
    }
    if ctx.requires_libcronet {
        let mut paths = vec![ctx.data_dir.to_path_buf()];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        if let Ok(joined) = std::env::join_paths(paths) {
            cmd = cmd.env("PATH", joined);
        }
    }
    let (mut receiver, child) = match cmd.spawn() {
        Ok(r) => r,
        Err(e) => return StartOutcome::Crashed(e.to_string()),
    };

    let child_pid = child.pid();
    *state.process.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
    *state.pid.lock().unwrap_or_else(|e| e.into_inner()) = Some(child_pid);
    *state.mode.lock().unwrap_or_else(|e| e.into_inner()) = ctx.vpn_mode.clone();
    *state.engine.lock().unwrap_or_else(|e| e.into_inner()) = ctx.engine.clone();

    let app_clone = app.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<bool>();
    let ready_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(ready_tx)));
    let expected_pid = child_pid;
    let log_prefix = ctx.log_prefix().to_string();
    let terminate_msg_fn = {
        let engine = ctx.engine.clone();
        move |code: Option<i32>| -> String {
            let name = match &engine {
                vpn::VpnEngine::SingBox => "sing-box",
                vpn::VpnEngine::Xray => "xray",
            };
            format!(
                "{name} exited (code: {})",
                code.map(|c| c.to_string()).unwrap_or("?".into())
            )
        }
    };
    let is_ready_fn = {
        let engine = ctx.engine.clone();
        move |line: &str| -> bool {
            match &engine {
                vpn::VpnEngine::SingBox => line.contains("sing-box started"),
                vpn::VpnEngine::Xray => line.contains("Xray") && line.contains("started"),
            }
        }
    };

    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = receiver.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !line.is_empty() {
                        if is_ready_fn(&line) {
                            if let Some(tx) = ready_tx.lock().await.take() {
                                let _ = tx.send(true);
                            }
                        }
                        // Префикс "[xray] " добавляется только для Xray — чтобы
                        // фронтенд мог визуально разделить логи двух ядер.
                        let prefixed = if log_prefix.is_empty() {
                            line
                        } else {
                            format!("{log_prefix}{line}")
                        };
                        let _ = app_clone.emit("singbox-log", prefixed);
                    }
                }
                CommandEvent::Terminated(status) => {
                    if let Some(tx) = ready_tx.lock().await.take() {
                        let _ = tx.send(false);
                    }
                    // Очищаем state только если PID совпадает (защита от race при retry).
                    let mut should_emit_terminated = false;
                    if let Some(st) = app_clone.try_state::<VpnState>() {
                        let current_pid = *st.pid.lock().unwrap_or_else(|e| e.into_inner());
                        if current_pid == Some(expected_pid) {
                            should_emit_terminated = st
                                .ready_session
                                .compare_exchange(session_id, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                                && st.session_generation.load(Ordering::SeqCst) == session_id;
                            let port = *st.proxy_port.lock().unwrap_or_else(|e| e.into_inner());
                            clear_owned_system_proxy(port);
                            let _ = st.process.lock().unwrap_or_else(|e| e.into_inner()).take();
                            let _ = st.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
                            // If the primary core exits, the helper router must not stay behind.
                            let helper_pid = st
                                .pid_helper
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            let _ = st
                                .process_helper
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            if let Some(hpid) = helper_pid {
                                graceful_kill_pid(hpid);
                            }
                            let bypass_ip = st
                                .bypass_route_ip
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            if let Some(route) = bypass_ip {
                                let _ = remove_server_bypass_route(route);
                            }
                        }
                    }
                    if should_emit_terminated {
                        let _ = app_clone.emit("singbox-terminated", terminate_msg_fn(status.code));
                    }
                    break;
                }
                _ => {}
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(ctx.timeout_secs), ready_rx).await {
        Ok(Ok(true)) => {
            if ctx.should_set_system_proxy() {
                if let Err(e) = mark_system_proxy_owned(ctx.proxy_port) {
                    return StartOutcome::Crashed(e);
                }
            }
            StartOutcome::Ready
        }
        Ok(Ok(false)) | Ok(Err(_)) => {
            StartOutcome::Crashed(format!("{} terminated with error", ctx.sidecar_name()))
        }
        Err(_) => {
            if matches!(ctx.engine, vpn::VpnEngine::Xray)
                && wait_for_xray_loopback(ctx.proxy_port, Duration::from_secs(1)).await
            {
                if ctx.should_set_system_proxy() {
                    if let Err(e) = mark_system_proxy_owned(ctx.proxy_port) {
                        return StartOutcome::Crashed(e);
                    }
                }
                return StartOutcome::Ready;
            }
            let failed_pid = {
                let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
                let _ = state
                    .process
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                pid
            };
            if let Some(pid) = failed_pid {
                let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
            }
            StartOutcome::Timeout
        }
    }
}

/// Резолвит server host в IP. Если host уже IP — возвращает его,
/// иначе делает DNS-lookup через системный резолвер.
fn is_loopback_port_open(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

async fn wait_for_xray_loopback(proxy_port: u16, timeout: Duration) -> bool {
    let socks_port = proxy_port.saturating_add(1);
    let deadline = Instant::now() + timeout;
    loop {
        let http_ready =
            tauri::async_runtime::spawn_blocking(move || is_loopback_port_open(proxy_port))
                .await
                .unwrap_or(false);
        let socks_ready =
            tauri::async_runtime::spawn_blocking(move || is_loopback_port_open(socks_port))
                .await
                .unwrap_or(false);
        if http_ready && socks_ready {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn resolve_server_ipv4(host: &str) -> Result<std::net::Ipv4Addr, String> {
    use std::net::{IpAddr, ToSocketAddrs};
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => return Ok(ip),
        Ok(IpAddr::V6(_)) => {
            return Err(format!(
                "Xray TUN requires an IPv4 server address; IPv6-only host '{host}' is not supported"
            ));
        }
        Err(_) => {}
    }
    // ToSocketAddrs требует port — используем 443 как заглушку, возьмём только IP.
    let addr_iter = (host, 443u16)
        .to_socket_addrs()
        .map_err(|e| format!("DNS lookup failed for '{host}': {e}"))?;
    addr_iter
        .filter_map(|sa| match sa.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .next()
        .ok_or_else(|| format!("no IPv4 address for host '{host}'"))
}

/// Определяет реальный gateway (default route) до старта TUN.
/// Парсит вывод `route print 0.0.0.0`. Возвращает IP шлюза или ошибку.
fn parse_default_gateway_from_route_print(stdout: &str) -> Result<std::net::Ipv4Addr, String> {
    let mut best: Option<(u32, std::net::Ipv4Addr)> = None;

    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 || cols[0] != "0.0.0.0" || cols[1] != "0.0.0.0" {
            continue;
        }
        let Ok(gateway) = cols[2].parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        if gateway.is_unspecified() {
            continue;
        }
        let metric = cols
            .last()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        if best.is_none_or(|(best_metric, _)| metric < best_metric) {
            best = Some((metric, gateway));
        }
    }

    best.map(|(_, gateway)| gateway)
        .ok_or_else(|| "default gateway not found".into())
}

#[cfg(windows)]
fn detect_default_gateway() -> Result<std::net::Ipv4Addr, String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("route print: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Ok(gw) = parse_default_gateway_from_route_print(&stdout) {
        return Ok(gw);
    }
    // Формат строки: "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     35"
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            if let Ok(gw) = cols[2].parse::<std::net::Ipv4Addr>() {
                // Исключаем TUN-интерфейс E13VPN (его gateway тоже будет 0.0.0.0 после старта).
                if !gw.is_unspecified() {
                    return Ok(gw);
                }
            }
        }
    }
    Err("default gateway not found".into())
}

#[cfg(not(windows))]
fn detect_default_gateway() -> Result<std::net::Ipv4Addr, String> {
    Err("detect_default_gateway: windows-only".into())
}

/// Добавляет маршрут к IP сервера через реальный gateway (в обход TUN).
/// Без этого маршрута TUN перехватывает трафик к серверу и создаёт петлю.
#[cfg(windows)]
fn add_server_bypass_route(
    server_ip: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
) -> Result<OwnedBypassRoute, String> {
    use std::os::windows::process::CommandExt;
    let ip_str = server_ip.to_string();
    let gw_str = gateway.to_string();
    let output = std::process::Command::new("route")
        .args(["add", &ip_str, "mask", "255.255.255.255", &gw_str])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| format!("route add {server_ip} via {gateway}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("route add {server_ip} via {gateway} failed")
        } else {
            format!("route add {server_ip} via {gateway} failed: {stderr}")
        });
    }
    Ok(OwnedBypassRoute { server_ip, gateway })
}

#[cfg(not(windows))]
fn add_server_bypass_route(
    server_ip: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
) -> Result<OwnedBypassRoute, String> {
    Ok(OwnedBypassRoute { server_ip, gateway })
}

/// Удаляет ранее добавленный bypass-route. Вызывается в cleanup_vpn/stop_vpn.
fn remove_server_bypass_route(route: OwnedBypassRoute) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new("route")
            .args([
                "delete",
                &route.server_ip.to_string(),
                "mask",
                "255.255.255.255",
                &route.gateway.to_string(),
            ])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| {
                format!(
                    "route delete {} via {}: {e}",
                    route.server_ip, route.gateway
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                format!(
                    "route delete {} via {} failed",
                    route.server_ip, route.gateway
                )
            } else {
                format!(
                    "route delete {} via {} failed: {stderr}",
                    route.server_ip, route.gateway
                )
            });
        }
    }
    #[cfg(not(windows))]
    {
        let _ = route;
    }
    Ok(())
}

/// Конфигурирует TUN-интерфейс после запуска tun2socks: IP, DNS, default route.
/// xjasonlyu/tun2socks сам этого не делает — только создаёт wintun-адаптер.
///
/// Следует официальному гайду xjasonlyu/tun2socks wiki + issue #327 (DNS is
/// mandatory, иначе DNS-запросы не идут через TUN даже при правильном routing).
///
/// Используется RFC 2544 benchmark-диапазон 198.18.0.0/30 для TUN, чтобы не
/// конфликтовать с sing-box'овым 172.18.0.1/30.
#[allow(dead_code)]
#[cfg(windows)]
fn configure_tun_interface() -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    fn run_netsh(args: &[&str]) -> Result<(std::process::ExitStatus, String), String> {
        let out = std::process::Command::new("netsh")
            .args(args)
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("netsh: {e}"))?;
        Ok((
            out.status,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    // Wintun-адаптер может регистрироваться несколько сотен миллисекунд после
    // того, как tun2socks напечатает [STACK]. Ретраим set address несколько раз.
    let iface_name_arg = format!("name={}", TUN_INTERFACE_NAME);

    // 1. IP на TUN (198.18.0.1/30 — 4 адреса, хватает с избытком).
    let mut set_addr_err = String::new();
    for attempt in 0..5 {
        std::thread::sleep(Duration::from_millis(200 + attempt * 200));
        let (status, stderr) = run_netsh(&[
            "interface",
            "ipv4",
            "set",
            "address",
            &iface_name_arg,
            "source=static",
            "addr=198.18.0.1",
            "mask=255.255.255.252",
            "gateway=none",
        ])?;
        if status.success() {
            set_addr_err.clear();
            break;
        }
        set_addr_err = stderr;
    }
    if !set_addr_err.is_empty() {
        return Err(format!("netsh set address failed: {set_addr_err}"));
    }

    // 2. DNS на TUN (issue #327). Google primary + Cloudflare secondary.
    //    register=none: не публиковать в DNS-suffix. validate=no: не пинговать DNS при установке.
    let (_, _) = run_netsh(&[
        "interface",
        "ipv4",
        "set",
        "dnsservers",
        &iface_name_arg,
        "static",
        "address=8.8.8.8",
        "register=none",
        "validate=no",
    ])?;
    let (_, _) = run_netsh(&[
        "interface",
        "ipv4",
        "add",
        "dnsservers",
        &iface_name_arg,
        "address=1.1.1.1",
        "index=2",
        "validate=no",
    ])?;

    // 3. Default route через TUN (metric=1 — выше системной).
    //    Маршруты к серверу (bypass_route_ip) уже добавлены ранее через real
    //    gateway с /32 маской — они специфичнее, default route их не перекроет.
    let (r_status, r_err) = run_netsh(&[
        "interface",
        "ipv4",
        "add",
        "route",
        "0.0.0.0/0",
        TUN_INTERFACE_NAME,
        "198.18.0.1",
        "metric=1",
    ])?;
    if !r_status.success() && !r_err.contains("already") && !r_err.is_empty() {
        return Err(format!("netsh add route failed: {r_err}"));
    }

    Ok(())
}

#[allow(dead_code)]
#[cfg(not(windows))]
fn configure_tun_interface() -> Result<(), String> {
    Err("configure_tun_interface: windows-only".into())
}

/// Запускает tun2socks поверх работающего Xray-SOCKS-инбаунда.
/// tun2socks создаёт TUN-интерфейс "E13VPN" (wintun) и маршрутизирует весь
/// трафик в socks5://127.0.0.1:<socks_port>.
async fn attempt_start_singbox_router(
    app: &AppHandle,
    state: &State<'_, VpnState>,
    config_str: &str,
    data_dir: &std::path::Path,
    timeout_secs: u64,
    session_id: u64,
) -> StartOutcome {
    let mut cmd = match app.shell().sidecar("sing-box") {
        Ok(c) => c.args(["run", "-c", config_str]),
        Err(e) => return StartOutcome::Crashed(format!("sing-box router sidecar: {e}")),
    };
    cmd = cmd.current_dir(data_dir);

    let (mut receiver, child) = match cmd.spawn() {
        Ok(r) => r,
        Err(e) => return StartOutcome::Crashed(format!("sing-box router spawn: {e}")),
    };

    let child_pid = child.pid();
    *state
        .process_helper
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(child);
    *state.pid_helper.lock().unwrap_or_else(|e| e.into_inner()) = Some(child_pid);

    let app_clone = app.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<bool>();
    let ready_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(ready_tx)));
    let expected_pid = child_pid;

    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = receiver.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !line.is_empty() {
                        if line.contains("sing-box started") {
                            if let Some(tx) = ready_tx.lock().await.take() {
                                let _ = tx.send(true);
                            }
                        }
                        let _ = app_clone.emit("singbox-log", format!("[router] {line}"));
                    }
                }
                CommandEvent::Terminated(status) => {
                    if let Some(tx) = ready_tx.lock().await.take() {
                        let _ = tx.send(false);
                    }
                    let mut should_emit_terminated = false;
                    if let Some(st) = app_clone.try_state::<VpnState>() {
                        let current_pid = *st.pid_helper.lock().unwrap_or_else(|e| e.into_inner());
                        if current_pid == Some(expected_pid) {
                            should_emit_terminated = st
                                .ready_session
                                .compare_exchange(session_id, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                                && st.session_generation.load(Ordering::SeqCst) == session_id
                                && st.pid.lock().unwrap_or_else(|e| e.into_inner()).is_some();
                            let _ = st
                                .process_helper
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            let _ = st
                                .pid_helper
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            let bypass_ip = st
                                .bypass_route_ip
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            if let Some(route) = bypass_ip {
                                let _ = remove_server_bypass_route(route);
                            }
                        }
                    }
                    let code = status.code.map(|c| c.to_string()).unwrap_or("?".into());
                    let message = format!("sing-box router exited (code: {code})");
                    let _ = app_clone.emit("singbox-log", format!("[router] {message}"));
                    if should_emit_terminated {
                        let _ = app_clone.emit("singbox-terminated", message);
                    }
                    break;
                }
                _ => {}
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(timeout_secs), ready_rx).await {
        Ok(Ok(true)) => StartOutcome::Ready,
        Ok(Ok(false)) | Ok(Err(_)) => StartOutcome::Crashed("sing-box router terminated".into()),
        Err(_) => {
            let failed_pid = {
                let pid = state
                    .pid_helper
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                let _ = state
                    .process_helper
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                pid
            };
            if let Some(pid) = failed_pid {
                let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
            }
            StartOutcome::Timeout
        }
    }
}

#[allow(dead_code)]
async fn attempt_start_tun2socks(
    app: &AppHandle,
    state: &State<'_, VpnState>,
    socks_port: u16,
    _server_ip: std::net::Ipv4Addr,
    data_dir: &std::path::Path,
    timeout_secs: u64,
) -> StartOutcome {
    // xjasonlyu/tun2socks CLI: поддерживает только -device/-proxy/-loglevel/-mtu.
    // Нет флага -exclude — исключение сервера из TUN делается через OS routing
    // (add_server_bypass_route, вызван в start_vpn до этого хелпера).
    let proxy_arg = format!("socks5://127.0.0.1:{socks_port}");
    // Унифицированный формат tun:// (README + issue #46) — на Windows создаёт
    // wintun-адаптер с указанным именем. wintun:// как scheme не поддерживается.
    let device_arg = format!("tun://{}", TUN_INTERFACE_NAME);

    let args: Vec<&str> = vec![
        "-device",
        &device_arg,
        "-proxy",
        &proxy_arg,
        "-loglevel",
        "info",
    ];

    let mut cmd = match app.shell().sidecar("tun2socks") {
        Ok(c) => c.args(args),
        Err(e) => return StartOutcome::Crashed(format!("tun2socks sidecar: {e}")),
    };
    // wintun.dll лежит в data_dir (копируется в start_vpn для sing-box-TUN; для Xray+TUN
    // тот же копир срабатывает т.к. mode==Tun). tun2socks тоже грузит wintun.dll из cwd.
    cmd = cmd.current_dir(data_dir);

    let (mut receiver, child) = match cmd.spawn() {
        Ok(r) => r,
        Err(e) => return StartOutcome::Crashed(format!("tun2socks spawn: {e}")),
    };

    let child_pid = child.pid();
    *state
        .process_helper
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(child);
    *state.pid_helper.lock().unwrap_or_else(|e| e.into_inner()) = Some(child_pid);

    let app_clone = app.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<bool>();
    let ready_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(ready_tx)));
    let expected_pid = child_pid;

    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = receiver.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !line.is_empty() {
                        // xjasonlyu/tun2socks логирует "[INFO] [STACK] ..." после инициализации.
                        // Берём stack-init как маркер готовности.
                        if (line.contains("[STACK]") || line.contains("stack"))
                            && !line.contains("error")
                        {
                            if let Some(tx) = ready_tx.lock().await.take() {
                                let _ = tx.send(true);
                            }
                        }
                        let _ = app_clone.emit("singbox-log", format!("[tun2socks] {line}"));
                    }
                }
                CommandEvent::Terminated(status) => {
                    if let Some(tx) = ready_tx.lock().await.take() {
                        let _ = tx.send(false);
                    }
                    if let Some(st) = app_clone.try_state::<VpnState>() {
                        let current_pid = *st.pid_helper.lock().unwrap_or_else(|e| e.into_inner());
                        if current_pid == Some(expected_pid) {
                            let _ = st
                                .process_helper
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                            let _ = st
                                .pid_helper
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .take();
                        }
                    }
                    let code = status.code.map(|c| c.to_string()).unwrap_or("?".into());
                    let _ =
                        app_clone.emit("singbox-log", format!("[tun2socks] exited (code: {code})"));
                    break;
                }
                _ => {}
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(timeout_secs), ready_rx).await {
        Ok(Ok(true)) => StartOutcome::Ready,
        Ok(Ok(false)) | Ok(Err(_)) => StartOutcome::Crashed("tun2socks terminated".into()),
        Err(_) => {
            let failed_pid = {
                let pid = state
                    .pid_helper
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                let _ = state
                    .process_helper
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                pid
            };
            if let Some(pid) = failed_pid {
                let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
            }
            StartOutcome::Timeout
        }
    }
}

/// Refreshes the WinTUN runtime copy from the bundled, pinned DLL.
fn ensure_wintun_dll(app: &AppHandle, data_dir: &std::path::Path) -> Result<(), String> {
    let candidates = {
        let mut c = Vec::new();
        if let Ok(res) = app.path().resource_dir() {
            c.push(res.join("wintun.dll"));
            c.push(res.join("binaries").join("wintun.dll"));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                c.push(dir.join("wintun.dll"));
                c.push(dir.join("binaries").join("wintun.dll"));
            }
        }
        c
    };
    let src = candidates
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| "wintun.dll not found".to_string())?
        .clone();
    let wintun_data = data_dir.join("wintun.dll");
    refresh_verified_runtime_file(&src, &wintun_data, EXPECTED_WINTUN_SHA256, "wintun.dll")
}

fn ensure_libcronet_dll(app: &AppHandle, data_dir: &std::path::Path) -> Result<(), String> {
    let candidates = {
        let mut c = Vec::new();
        if let Ok(res) = app.path().resource_dir() {
            c.push(res.join(LIBCRONET_BINARY_NAME));
            c.push(res.join("binaries").join(LIBCRONET_BINARY_NAME));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                c.push(dir.join(LIBCRONET_BINARY_NAME));
                c.push(dir.join("binaries").join(LIBCRONET_BINARY_NAME));
            }
        }
        c
    };
    let src = candidates
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| "libcronet.dll not found; NaiveProxy requires it".to_string())?
        .clone();
    let dll_data = data_dir.join(LIBCRONET_BINARY_NAME);
    refresh_verified_runtime_file(&src, &dll_data, EXPECTED_LIBCRONET_SHA256, "libcronet.dll")
}

/// Находит путь к бандленному бинарнику по полному имени (с triple-суффиксом).
/// Проверяет resource_dir/binaries/<name>, exe_dir/<name> и exe_dir/<short>.exe
/// (short — имя без triple-суффикса, как Tauri копирует externalBin в dev-режиме:
///  xray-x86_64-pc-windows-msvc.exe → xray.exe в target/debug/).
/// Возвращает None если ничего не найдено — верификация пропускается
/// (Tauri sidecar() сам корректно резолвит бинарник при spawn'е).
fn find_bundled_binary(app: &AppHandle, name: &str) -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(res) = app.path().resource_dir() {
        candidates.push(res.join("binaries").join(name));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(name));
            // Dev-режим: Tauri копирует externalBin без triple-суффикса.
            // Из "xray-x86_64-pc-windows-msvc.exe" делаем "xray.exe".
            if let Some(short) = short_binary_name(name) {
                candidates.push(dir.join(short));
            }
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// Из "<stem>-x86_64-pc-windows-msvc.exe" → "<stem>.exe". None для других форматов.
fn short_binary_name(full: &str) -> Option<String> {
    let without_ext = full.strip_suffix(".exe")?;
    let stem = without_ext.strip_suffix("-x86_64-pc-windows-msvc")?;
    Some(format!("{stem}.exe"))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn start_vpn(
    app: AppHandle,
    state: State<'_, VpnState>,
    uri: String,
    bypass_vpn: Vec<String>,
    bypass_apps: Vec<String>,
    mode: String,
    system_proxy: Option<bool>,
    random_proxy_port: Option<bool>,
    fixed_proxy_port: Option<u16>,
    route_policy: Option<String>,
) -> Result<(), String> {
    let session_id = state.session_generation.fetch_add(1, Ordering::SeqCst) + 1;
    state.ready_session.store(0, Ordering::SeqCst);
    let _operation_guard = state.operation_lock.lock().await;
    ensure_current_session(state.inner(), session_id)?;

    let vpn_mode = vpn::VpnMode::from_str(&mode);
    let route_policy = vpn::RoutePolicy::from_str(route_policy.as_deref().unwrap_or("bypass"));
    let use_system_proxy = system_proxy.unwrap_or(true);
    let use_random_proxy_port = random_proxy_port.unwrap_or(true);

    // TUN cooldown: wait at least 2s after previous TUN stop
    if vpn_mode == vpn::VpnMode::Tun {
        let last_stop = *state
            .last_tun_stop
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(stop_time) = last_stop {
            let elapsed = stop_time.elapsed();
            if elapsed < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_secs(2) - elapsed).await;
            }
        }
        ensure_current_session(state.inner(), session_id)?;
    }

    if vpn_mode == vpn::VpnMode::Tun && !is_elevated() {
        return Err("TUN requires administrator privileges".into());
    }

    let params = vpn::parse_proxy_uri(&uri)?;
    let engine = params.engine();

    // Belt-and-suspenders: в Lite-сборке парсер уже отверг бы xhttp/splithttp,
    // но если что-то просочилось — здесь явно отказываем и показываем куда идти.
    #[cfg(not(feature = "xhttp"))]
    if engine == vpn::VpnEngine::Xray {
        return Err(format!(
            "Транспорт xhttp/splithttp не поддерживается в Lite. Скачайте Full: {}",
            vpn::FULL_VERSION_URL
        ));
    }

    // Generate local proxy port and secret for each session.
    let proxy_port = selected_proxy_port(use_random_proxy_port, fixed_proxy_port)?;
    let clash_secret = random_secret();
    *state.proxy_port.lock().unwrap_or_else(|e| e.into_inner()) = proxy_port;
    *state.clash_secret.lock().unwrap_or_else(|e| e.into_inner()) = clash_secret.clone();
    if !use_random_proxy_port {
        let _ = app.emit(
            "singbox-log",
            format!("[proxy] fixed local port selected: 127.0.0.1:{proxy_port}"),
        );
    }
    if vpn_mode == vpn::VpnMode::Proxy && !use_system_proxy {
        let _ = app.emit(
            "singbox-log",
            "[proxy] Windows system proxy is disabled; configure apps manually",
        );
    }

    // Clash API доступен только с sing-box. Xray имеет другой API — фронтенд
    // должен обрабатывать отсутствие события gracefully (IP-reveal через прямой
    // запрос через system proxy).
    if engine == vpn::VpnEngine::SingBox {
        let _ = app.emit(
            "clash-api-params",
            serde_json::json!({
                "enabled": true,
                "secret": clash_secret,
                "port": 9090
            }),
        );
    } else {
        let _ = app.emit(
            "clash-api-params",
            serde_json::json!({
                "enabled": false
            }),
        );
        let _ = app.emit(
            "singbox-log",
            "[xray] Clash API недоступен для xhttp/splithttp (используется Xray-ядро)",
        );
        if !bypass_apps.is_empty() {
            let message = if vpn_mode == vpn::VpnMode::Tun {
                "[xray] bypass_apps will be handled by the sing-box TUN router"
            } else {
                "[xray] bypass_apps is not supported in Xray proxy mode"
            };
            let _ = app.emit("singbox-log", message);
        }
    }

    // Генерация конфига зависит от ядра.
    let config_json = match engine {
        vpn::VpnEngine::SingBox => serde_json::to_string_pretty(&vpn::generate_singbox_config(
            &params,
            &bypass_vpn,
            &bypass_apps,
            &vpn_mode,
            &route_policy,
            proxy_port,
            &clash_secret,
        ))
        .map_err(|e| e.to_string())?,
        vpn::VpnEngine::Xray => {
            let vless_params = params
                .as_vless()
                .ok_or("Xray supports only VLESS configs")?;
            serde_json::to_string_pretty(&vpn_xray::generate_xray_config(
                vless_params,
                &bypass_vpn,
                &bypass_apps,
                &vpn_mode,
                &route_policy,
                proxy_port,
            ))
            .map_err(|e| e.to_string())?
        }
    };

    let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    cleanup_runtime_config_files(&data_dir);
    if params.requires_libcronet() {
        ensure_libcronet_dll(&app, &data_dir)?;
    }
    let config_filename = match engine {
        vpn::VpnEngine::SingBox => "singbox.json",
        vpn::VpnEngine::Xray => "xray.json",
    };
    let config_path = data_dir.join(config_filename);
    std::fs::write(&config_path, &config_json).map_err(|e| e.to_string())?;

    // wintun.dll нужен для любого TUN (sing-box или Xray+tun2socks).
    if vpn_mode == vpn::VpnMode::Tun {
        ensure_wintun_dll(&app, &data_dir)?;
    }

    // Graceful kill previous process (primary + helper).
    let prev_pid = {
        let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
        let _ = state
            .process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        pid
    };
    let prev_helper_pid = {
        let pid = state
            .pid_helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let _ = state
            .process_helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        pid
    };
    if let Some(pid) = prev_helper_pid {
        let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
    }
    if let Some(pid) = prev_pid {
        let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
    }

    // Kill orphan процессы всех ядер (сессия могла остаться после краша).
    let _ = tauri::async_runtime::spawn_blocking(kill_orphan_all).await;
    ensure_current_session(state.inner(), session_id).inspect_err(|_| {
        remove_loaded_runtime_config(&app, &config_path);
    })?;

    if !use_random_proxy_port {
        ensure_fixed_proxy_ports_available(&engine, &vpn_mode, proxy_port)?;
    }

    // SHA256 verify primary бинарника (sing-box или xray).
    // Best-effort: если бинарник не найден по известным путям (например, в dev-режиме
    // Tauri копирует без triple-суффикса и мы его не угадали) — верификацию пропускаем.
    // Sidecar spawn всё равно сработает — Tauri сам резолвит externalBin.
    match engine {
        vpn::VpnEngine::SingBox => {
            if let Some(p) = find_bundled_binary(&app, SINGBOX_BINARY_NAME) {
                verify_singbox_binary(&p)?;
            }
        }
        vpn::VpnEngine::Xray => {
            if let Some(p) = find_bundled_binary(&app, XRAY_BINARY_NAME) {
                verify_xray_binary(&p)?;
            }
            if vpn_mode == vpn::VpnMode::Tun {
                if let Some(p) = find_bundled_binary(&app, SINGBOX_BINARY_NAME) {
                    verify_singbox_binary(&p)?;
                }
            }
        }
    }

    let config_str = config_path
        .to_str()
        .ok_or("invalid config path")?
        .to_string();

    // TUN pre-warm: очистить stale wintun adapter и подгрузить драйвер.
    // Касается и sing-box-TUN, и Xray+tun2socks — оба используют wintun.
    if vpn_mode == vpn::VpnMode::Tun {
        let _ = tauri::async_runtime::spawn_blocking(|| {
            cleanup_stale_tun_adapter();
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("sc")
                    .args(["start", "wintun"])
                    .creation_flags(0x08000000)
                    .output();
            }
        })
        .await;
    }

    // === Запуск primary ядра с retry ===
    // sing-box TUN: до 3 попыток (wintun race). Proxy и Xray: 1 попытка.
    let max_attempts: u32 = match (&engine, &vpn_mode) {
        (vpn::VpnEngine::SingBox, vpn::VpnMode::Tun) => 3,
        _ => 1,
    };
    let primary_timeout_secs: u64 = match (&engine, &vpn_mode) {
        (vpn::VpnEngine::SingBox, vpn::VpnMode::Tun) => 15, // > sing-box wintun internal timeout
        (vpn::VpnEngine::Xray, _) => 8,
        _ => 5,
    };

    let mut last_err = String::new();
    let ctx = PrimaryEngineCtx {
        engine: &engine,
        config_str: &config_str,
        data_dir: &data_dir,
        vpn_mode: &vpn_mode,
        timeout_secs: primary_timeout_secs,
        proxy_port,
        system_proxy: use_system_proxy,
        requires_libcronet: params.requires_libcronet(),
    };

    let mut primary_ready = false;
    for attempt in 1..=max_attempts {
        if attempt > 1 {
            let _ = app.emit(
                "singbox-log",
                format!(
                    "[retry] primary attempt {}/{} (timeout {}s)...",
                    attempt, max_attempts, primary_timeout_secs
                ),
            );
        }
        let outcome = attempt_start_engine(&app, &state, &ctx, session_id).await;
        ensure_current_session(state.inner(), session_id).inspect_err(|_| {
            remove_loaded_runtime_config(&app, &config_path);
        })?;
        match outcome {
            StartOutcome::Ready => {
                primary_ready = true;
                break;
            }
            StartOutcome::Crashed(e) => {
                last_err = e;
                if attempt < max_attempts {
                    let _ = app.emit(
                        "singbox-log",
                        format!("[retry] crashed (driver warming up): {}", last_err),
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            StartOutcome::Timeout => {
                last_err = format!(
                    "{} did not start within {}s",
                    ctx.sidecar_name(),
                    primary_timeout_secs
                );
                if attempt < max_attempts {
                    let _ = app.emit(
                        "singbox-log",
                        format!(
                            "[retry] timeout after {}s, retrying...",
                            primary_timeout_secs
                        ),
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = tauri::async_runtime::spawn_blocking(kill_orphan_all).await;
                }
            }
        }
    }
    if !primary_ready {
        remove_loaded_runtime_config(&app, &config_path);
        return Err(last_err);
    }
    if engine == vpn::VpnEngine::Xray
        && !wait_for_xray_loopback(proxy_port, Duration::from_secs(2)).await
    {
        cleanup_vpn(&state);
        remove_loaded_runtime_config(&app, &config_path);
        return Err("xray started but HTTP/SOCKS loopback inbounds are not reachable".into());
    }
    remove_loaded_runtime_config(&app, &config_path);

    // Для Xray+TUN дополнительно поднимаем tun2socks поверх SOCKS-инбаунда.
    if engine == vpn::VpnEngine::Xray && vpn_mode == vpn::VpnMode::Tun {
        // Резолвим IP сервера (чтобы исключить его из TUN и добавить маршрут через real gateway).
        let server_ip = resolve_server_ipv4(params.server_host()).inspect_err(|_e| {
            // Если не получилось — primary уже поднят, нужно откатить.
            cleanup_vpn(&state);
        })?;

        // Ставим route к серверу через real gateway ДО запуска tun2socks.
        #[cfg(windows)]
        {
            if let Ok(gw) = detect_default_gateway() {
                match add_server_bypass_route(server_ip, gw) {
                    Ok(route) => {
                        *state
                            .bypass_route_ip
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = Some(route);
                        let _ = app.emit(
                            "singbox-log",
                            format!("[xray] server bypass route added: {server_ip} via {gw}"),
                        );
                    }
                    Err(error) => {
                        let _ = app.emit(
                            "singbox-log",
                            format!("[xray] server bypass route was not added: {error}"),
                        );
                    }
                }
            } else {
                let _ = app.emit("singbox-log",
                    "[xray] default gateway not detected — bypass route skipped (risk of routing loop)");
            }
        }

        // SOCKS-инбаунд xray открыт на proxy_port + 1 (см. vpn_xray.rs).
        let socks_port = proxy_port.saturating_add(1);
        let router_config_json =
            serde_json::to_string_pretty(&vpn::generate_singbox_xray_tun_router_config(
                &bypass_vpn,
                &bypass_apps,
                &server_ip.to_string(),
                &route_policy,
                socks_port,
            ))
            .map_err(|e| e.to_string())?;
        let router_config_path = data_dir.join("xray-singbox-router.json");
        std::fs::write(&router_config_path, router_config_json).map_err(|e| e.to_string())?;
        let router_config_str = router_config_path
            .to_str()
            .ok_or("invalid router config path")?
            .to_string();
        let router_timeout_secs: u64 = 15;

        let mut router_ready = false;
        let router_max_attempts = 3;
        for attempt in 1..=router_max_attempts {
            if attempt > 1 {
                let _ = app.emit(
                    "singbox-log",
                    format!(
                        "[retry] router attempt {}/{}...",
                        attempt, router_max_attempts
                    ),
                );
            }
            match attempt_start_singbox_router(
                &app,
                &state,
                &router_config_str,
                &data_dir,
                router_timeout_secs,
                session_id,
            )
            .await
            {
                StartOutcome::Ready => {
                    router_ready = true;
                    break;
                }
                StartOutcome::Crashed(e) => {
                    last_err = format!("sing-box router: {e}");
                    if attempt < router_max_attempts {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let _ =
                            tauri::async_runtime::spawn_blocking(cleanup_stale_tun_adapter).await;
                    }
                }
                StartOutcome::Timeout => {
                    last_err =
                        format!("sing-box router did not start within {router_timeout_secs}s");
                    if attempt < router_max_attempts {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let _ =
                            tauri::async_runtime::spawn_blocking(cleanup_stale_tun_adapter).await;
                    }
                }
            }
            ensure_current_session(state.inner(), session_id).inspect_err(|_| {
                remove_loaded_runtime_config(&app, &router_config_path);
            })?;
        }
        remove_loaded_runtime_config(&app, &router_config_path);

        if !router_ready {
            // tun2socks не смог подняться — откатываем всё (xray, bypass route).
            cleanup_vpn(&state);
            return Err(last_err);
        }

        // tun2socks создал wintun-адаптер, но без IP и default-route.
        // Конфигурируем его через netsh (see configure_tun_interface doc).
        let cfg_err: Option<String> = None;
        if let Some(err) = cfg_err {
            // Не фатально — админ сможет настроить маршруты вручную.
            let _ = app.emit(
                "singbox-log",
                format!("[xray] TUN configuration failed — routing may not work: {err}"),
            );
        } else {
            let _ = app.emit(
                "singbox-log",
                format!("[xray] TUN router ready: E13VPN -> socks5://127.0.0.1:{socks_port}"),
            );
        }
    }

    ensure_current_session(state.inner(), session_id)?;
    let primary_alive = state
        .pid
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    let helper_required = engine == vpn::VpnEngine::Xray && vpn_mode == vpn::VpnMode::Tun;
    let helper_alive = !helper_required
        || state
            .pid_helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
    if !primary_alive || !helper_alive {
        cleanup_vpn(&state);
        return Err("VPN engine terminated before the session became ready".into());
    }
    state.ready_session.store(session_id, Ordering::SeqCst);

    Ok(())
}

#[tauri::command]
async fn update_tray_icon(app: AppHandle, connected: bool) -> Result<(), String> {
    let icon_name = if connected {
        "icons/1act.png"
    } else {
        "icons/2dis.png"
    };
    let icon_path = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join(icon_name);
    let image = Image::from_path(&icon_path).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_icon(Some(image)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn stop_vpn(state: State<'_, VpnState>) -> Result<(), String> {
    state.session_generation.fetch_add(1, Ordering::SeqCst);
    state.ready_session.store(0, Ordering::SeqCst);
    let _operation_guard = state.operation_lock.lock().await;

    // Helper (tun2socks) первым — снимает TUN до того как primary умрёт.
    let helper_pid = {
        let pid = state
            .pid_helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let _ = state
            .process_helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        pid
    };
    if let Some(pid) = helper_pid {
        let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
    }

    let (pid, had_process, mode) = {
        let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
        let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
        let had_process = guard.take().is_some();
        let mode = state.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
        (pid, had_process, mode)
    };
    if let Some(pid) = pid {
        let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
    }

    let port = *state.proxy_port.lock().unwrap_or_else(|e| e.into_inner());
    clear_owned_system_proxy(port);
    if mode == vpn::VpnMode::Tun && had_process {
        *state
            .last_tun_stop
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        let _ = tauri::async_runtime::spawn_blocking(cleanup_stale_tun_adapter).await;
    }

    // Снять bypass-route если был добавлен (Xray+TUN).
    let bypass_ip = state
        .bypass_route_ip
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(route) = bypass_ip {
        let _ =
            tauri::async_runtime::spawn_blocking(move || remove_server_bypass_route(route)).await;
    }

    Ok(())
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("DPAPI CryptProtectData failed".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as *mut _);
    };
    Ok(result)
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("DPAPI CryptUnprotectData failed".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as *mut _);
    };
    Ok(result)
}

#[tauri::command]
fn encrypt_string(value: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        let encrypted = dpapi_protect(value.as_bytes())?;
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
    }
    #[cfg(not(windows))]
    Ok(value)
}

#[tauri::command]
fn update_tray_labels(
    app: AppHandle,
    show_label: String,
    quit_label: String,
) -> Result<(), String> {
    let show_i = MenuItem::with_id(&app, "show", &show_label, true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let quit_i = MenuItem::with_id(&app, "quit", &quit_label, true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let menu = Menu::with_items(&app, &[&show_i, &quit_i]).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn validate_route(entry: String) -> (String, bool) {
    vpn::validate_route_entry(&entry)
}

#[tauri::command]
fn is_autostart_launch() -> bool {
    std::env::args().any(|arg| arg == "--e13-autostart")
}

#[tauri::command]
fn decrypt_string(value: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&value)
            .map_err(|e| e.to_string())?;
        let decrypted = dpapi_unprotect(&data)?;
        String::from_utf8(decrypted).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    Ok(value)
}

#[derive(Debug, Clone)]
struct SubscriptionUrl {
    url: reqwest::Url,
    safe_host: String,
}

fn validate_subscription_url(raw: &str) -> Result<SubscriptionUrl, String> {
    let url =
        reqwest::Url::parse(raw.trim()).map_err(|_| "invalid subscription URL".to_string())?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("subscription URL must use http or https".into()),
    }
    let safe_host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| "subscription URL must include a host".to_string())?
        .to_string();

    Ok(SubscriptionUrl { url, safe_host })
}

#[tauri::command]
async fn import_subscription_url(url: String) -> Result<subscription::SubscriptionImport, String> {
    let parsed = validate_subscription_url(&url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(format!("E13VPN+/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("failed to create subscription client: {e}"))?;

    let mut response = client.get(parsed.url).send().await.map_err(|e| {
        format!(
            "failed to download subscription from {}: {e}",
            parsed.safe_host
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "subscription server {} returned HTTP {}",
            parsed.safe_host, status
        ));
    }
    if response
        .content_length()
        .is_some_and(|len| len > subscription::MAX_SUBSCRIPTION_BODY_BYTES as u64)
    {
        return Err(format!(
            "subscription response from {} is too large",
            parsed.safe_host
        ));
    }

    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(subscription::MAX_SUBSCRIPTION_BODY_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("failed to read subscription from {}: {e}", parsed.safe_host))?
    {
        if bytes.len().saturating_add(chunk.len()) > subscription::MAX_SUBSCRIPTION_BODY_BYTES {
            return Err(format!(
                "subscription response from {} is too large",
                parsed.safe_host
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8(bytes).map_err(|_| {
        format!(
            "subscription response from {} is not UTF-8",
            parsed.safe_host
        )
    })?;

    subscription::parse_subscription_body(&body)
}

#[cfg(windows)]
fn cleanup_stale_proxy() {
    // Restore only a proxy endpoint marked as owned by a previous E13VPN+ session.
    // A localhost proxy configured by another application must remain untouched.
    let _ = vpn::release_system_proxy();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    cleanup_stale_proxy();
    cleanup_stale_tun_adapter();

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        clear_owned_system_proxy(0);
        kill_orphan_all();
        cleanup_stale_tun_adapter();
        default_hook(info);
    }));

    tauri::Builder::default()
        .manage(VpnState {
            process: Mutex::new(None),
            process_helper: Mutex::new(None),
            pid: Mutex::new(None),
            pid_helper: Mutex::new(None),
            engine: Mutex::new(vpn::VpnEngine::SingBox),
            mode: Mutex::new(vpn::VpnMode::Proxy),
            proxy_port: Mutex::new(0),
            clash_secret: Mutex::new(String::new()),
            last_tun_stop: Mutex::new(None),
            operation_lock: tokio::sync::Mutex::new(()),
            session_generation: AtomicU64::new(0),
            ready_session: AtomicU64::new(0),
            bypass_route_ip: Mutex::new(None),
        })
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--e13-autostart"]),
        ))
        .setup(|app| {
            if let Ok(data_dir) = app.path().app_data_dir() {
                cleanup_runtime_config_files(&data_dir);
            }
            #[cfg(windows)]
            {
                if let Some(win) = app.get_webview_window("main") {
                    let hwnd = win.hwnd().unwrap().0 as windows_sys::Win32::Foundation::HWND;
                    apply_dwm_borderless(hwnd);
                    install_borderless_subclass(hwnd);
                }
            }

            let show_i = MenuItem::with_id(app, "show", "Показать", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;
            let tray_icon_path = app
                .path()
                .resource_dir()
                .map_err(|e| e.to_string())?
                .join("icons/2dis.png");
            let tray_icon = Image::from_path(&tray_icon_path).map_err(|e| e.to_string())?;

            TrayIconBuilder::with_id("main")
                .menu(&menu)
                .tooltip("E13VPN+")
                .icon(tray_icon)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    "quit" => {
                        if let Some(state) = app.try_state::<VpnState>() {
                            cleanup_vpn(state.inner());
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            if win.is_visible().unwrap_or(false) {
                                let _ = win.hide();
                            } else {
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            start_vpn,
            stop_vpn,
            update_tray_icon,
            encrypt_string,
            decrypt_string,
            update_tray_labels,
            validate_route,
            is_autostart_launch,
            import_subscription_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn port_from_hash_keeps_room_for_xray_socks_port() {
        assert_eq!(port_from_hash(0), 49152);
        assert_eq!(port_from_hash((65534 - 49152) as u64), 65534);
    }

    #[test]
    fn random_port_never_returns_last_dynamic_port() {
        for _ in 0..1000 {
            assert!(random_port() <= 65534);
        }
    }

    #[test]
    fn fixed_proxy_port_defaults_to_2080() {
        assert_eq!(fixed_proxy_port(None).expect("default fixed port"), 2080);
    }

    #[test]
    fn fixed_proxy_port_rejects_reserved_and_last_port() {
        assert!(fixed_proxy_port(Some(1023)).is_err());
        assert!(fixed_proxy_port(Some(65535)).is_err());
    }

    #[test]
    fn selected_proxy_port_keeps_fixed_65534_for_xray_socks_room() {
        assert_eq!(
            selected_proxy_port(false, Some(65534)).expect("fixed port"),
            65534
        );
    }

    #[test]
    fn short_binary_name_preserves_hyphenated_stems() {
        assert_eq!(
            short_binary_name("sing-box-x86_64-pc-windows-msvc.exe").as_deref(),
            Some("sing-box.exe")
        );
        assert_eq!(
            short_binary_name("xray-x86_64-pc-windows-msvc.exe").as_deref(),
            Some("xray.exe")
        );
        assert_eq!(
            short_binary_name("tun2socks-x86_64-pc-windows-msvc.exe").as_deref(),
            Some("tun2socks.exe")
        );
    }

    #[test]
    fn resolve_server_ipv4_accepts_ipv4_literal() {
        assert_eq!(
            resolve_server_ipv4("203.0.113.10").expect("ipv4 literal"),
            Ipv4Addr::new(203, 0, 113, 10)
        );
    }

    #[test]
    fn resolve_server_ipv4_rejects_ipv6_literal() {
        let err = resolve_server_ipv4("2001:db8::1").expect_err("ipv6 literal should fail");
        assert!(err.contains("IPv6"));
    }

    #[test]
    fn parse_default_gateway_prefers_lowest_metric() {
        let route_print = r#"
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100     35
          0.0.0.0          0.0.0.0         10.0.0.1      10.0.0.20      5
        127.0.0.0        255.0.0.0         On-link       127.0.0.1    331
"#;
        assert_eq!(
            parse_default_gateway_from_route_print(route_print).expect("gateway"),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn validate_subscription_url_accepts_http_and_redacts_to_host() {
        let parsed =
            validate_subscription_url("https://sub.example.com/vip/private-token?client=desktop")
                .expect("valid subscription url");

        assert_eq!(parsed.safe_host, "sub.example.com");
        assert!(parsed.url.as_str().contains("/vip/private-token"));
    }

    #[test]
    fn validate_subscription_url_rejects_non_http_schemes() {
        let err = validate_subscription_url("file:///C:/secret.txt").expect_err("reject file URL");

        assert!(err.contains("http"));
    }

    #[test]
    fn refresh_verified_runtime_file_replaces_tampered_destination() {
        use sha2::{Digest, Sha256};

        let test_dir = std::env::temp_dir().join(format!(
            "e13vpn-runtime-refresh-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&test_dir).expect("create runtime test directory");
        let source = test_dir.join("source.dll");
        let destination = test_dir.join("runtime.dll");
        let trusted = b"trusted runtime bytes";
        std::fs::write(&source, trusted).expect("write trusted source");
        std::fs::write(&destination, b"tampered").expect("write tampered destination");
        let expected = format!("{:x}", Sha256::digest(trusted));

        refresh_verified_runtime_file(&source, &destination, &expected, "test runtime")
            .expect("refresh runtime file");

        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            trusted
        );
        let _ = std::fs::remove_dir_all(&test_dir);
    }
}
