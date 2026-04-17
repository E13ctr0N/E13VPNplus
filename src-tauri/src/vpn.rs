use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum VpnMode {
    Proxy,
    Tun,
}

impl VpnMode {
    pub fn from_str(s: &str) -> Self {
        if s == "tun" { VpnMode::Tun } else { VpnMode::Proxy }
    }
}

/// URL страницы релизов Full-версии — показывается в ошибке, когда Lite
/// отказывается от xhttp/splithttp. Меняется при ребрендинге/переезде репо.
/// В Full-сборке константа не используется (allow-dead) — оставлена для единства vpn.rs.
#[allow(dead_code)]
pub const FULL_VERSION_URL: &str = "https://github.com/procomp39/E13VPN/releases";

/// Какое VPN-ядро используется для данной конфигурации.
/// SingBox — все транспорты кроме xhttp/splithttp.
/// Xray — только xhttp/splithttp (sing-box их не умеет).
/// В Lite-сборке вариант Xray объявлен, но никогда не конструируется —
/// парсер отклоняет xhttp/splithttp до вызова engine().
#[derive(Debug, Clone, PartialEq)]
pub enum VpnEngine {
    SingBox,
    #[cfg_attr(not(feature = "xhttp"), allow(dead_code))]
    Xray,
}

#[derive(Debug, Clone)]
pub struct VlessParams {
    pub uuid: String,
    pub host: String,
    pub port: u16,
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
    pub flow: String,
    #[allow(dead_code)]
    pub name: String,
    // Transport
    pub transport_type: String, // "", "tcp", "ws", "http", "grpc", "quic", "httpupgrade", "xhttp", "splithttp"
    pub transport_path: String,
    pub transport_host: String,
    pub service_name: String,
    pub alpn: Vec<String>,
}

impl VlessParams {
    /// Выбирает VPN-ядро на основе транспорта: xhttp/splithttp → Xray, иначе sing-box.
    /// В Lite-сборке (без feature "xhttp") парсер отвергает xhttp/splithttp раньше —
    /// до engine() не доходит, вариант Xray никогда не конструируется.
    pub fn engine(&self) -> VpnEngine {
        match self.transport_type.as_str() {
            "xhttp" | "splithttp" => VpnEngine::Xray,
            _ => VpnEngine::SingBox,
        }
    }
}

fn percent_decode(s: &str) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    buf.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        buf.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// sing-box поддерживает только "xtls-rprx-vision"; варианты вроде
/// "xtls-rprx-vision-udp443" встречаются в URI, но sing-box их не принимает.
fn normalize_flow(raw: &str) -> String {
    let s = raw.trim();
    if s.starts_with("xtls-rprx-vision") {
        return "xtls-rprx-vision".to_string();
    }
    s.to_string()
}

/// Проверяет формат UUID (8-4-4-4-12 hex)
fn is_valid_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts.iter().zip(expected_lens.iter()).all(|(part, &len)| {
        part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// Допустимые значения параметра security
const ALLOWED_SECURITY: &[&str] = &["reality", "tls", "none", ""];

/// Допустимые значения параметра flow (после нормализации)
const ALLOWED_FLOW: &[&str] = &["", "xtls-rprx-vision"];

/// Допустимые значения параметра type (транспорт).
/// xhttp/splithttp поддерживаются через Xray-ядро (см. VlessParams::engine()),
/// остальные — через sing-box. В Lite-сборке xhttp/splithttp отсутствуют в списке
/// и отклоняются с сообщением-перенаправлением на Full-версию.
#[cfg(feature = "xhttp")]
const ALLOWED_TRANSPORT: &[&str] = &[
    "", "tcp", "ws", "http", "grpc", "quic", "httpupgrade", "xhttp", "splithttp",
];
#[cfg(not(feature = "xhttp"))]
const ALLOWED_TRANSPORT: &[&str] = &[
    "", "tcp", "ws", "http", "grpc", "quic", "httpupgrade",
];

pub fn parse_vless_uri(uri: &str) -> Result<VlessParams, String> {
    let uri = uri.trim();

    // Проверка максимальной длины (защита от DoS)
    if uri.len() > 10240 {
        return Err("URI слишком длинный (макс. 10 КБ)".into());
    }

    if !uri.starts_with("vless://") {
        return Err("не является vless:// URI".into());
    }
    let s = &uri[8..]; // strip scheme

    // Fragment (name)
    let (s, name) = if let Some(idx) = s.rfind('#') {
        (&s[..idx], percent_decode(&s[idx + 1..]))
    } else {
        (s, "без имени".into())
    };

    // UUID @ host:port ? query
    let (uuid, rest) = s
        .split_once('@')
        .ok_or("неверный формат: нет @")?;

    // Валидация UUID
    if !is_valid_uuid(uuid) {
        return Err(format!(
            "неверный UUID: ожидается формат xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, получено: {}",
            if uuid.len() > 50 { &uuid[..50] } else { uuid }
        ));
    }

    let (hostport, query) = if let Some(idx) = rest.find('?') {
        (&rest[..idx], &rest[idx + 1..])
    } else {
        (rest, "")
    };

    // host:port — берём последний ":" чтобы обработать IPv6
    let (host, port_s) = hostport
        .rsplit_once(':')
        .ok_or("неверный формат: нет порта")?;
    let port = port_s
        .parse::<u16>()
        .map_err(|_| format!("неверный порт: {port_s}"))?;

    // Порт 0 недопустим
    if port == 0 {
        return Err("порт не может быть 0".into());
    }

    // Валидация host: должен быть IP-адрес или валидный домен
    let clean_host = host.trim_matches(|c| c == '[' || c == ']'); // IPv6 brackets
    if clean_host.parse::<IpAddr>().is_err() && !is_valid_domain(clean_host) {
        return Err(format!("неверный хост: '{}'", if host.len() > 100 { &host[..100] } else { host }));
    }

    let params: HashMap<&str, &str> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();

    let security = params.get("security").unwrap_or(&"none").to_string();
    if !ALLOWED_SECURITY.contains(&security.as_str()) {
        return Err(format!(
            "неподдерживаемое значение security: '{}' (допустимо: reality, tls, none)",
            security
        ));
    }

    let flow = normalize_flow(params.get("flow").unwrap_or(&""));
    if !ALLOWED_FLOW.contains(&flow.as_str()) {
        return Err(format!(
            "неподдерживаемое значение flow: '{}' (допустимо: пусто, xtls-rprx-vision)",
            flow
        ));
    }

    // Transport
    let transport_type = params.get("type").unwrap_or(&"").to_lowercase();
    if !ALLOWED_TRANSPORT.contains(&transport_type.as_str()) {
        // В Lite-сборке xhttp/splithttp отсутствуют в ALLOWED_TRANSPORT — перехватываем
        // именно эту ситуацию, чтобы подсказать пользователю, где взять Full-версию.
        #[cfg(not(feature = "xhttp"))]
        if transport_type == "xhttp" || transport_type == "splithttp" {
            return Err(format!(
                "Транспорт '{}' требует E13VPN Full. Скачайте: {}",
                transport_type, FULL_VERSION_URL
            ));
        }
        return Err(format!(
            "неподдерживаемый транспорт: '{}' (допустимо: tcp, ws, http, grpc, quic, httpupgrade, xhttp, splithttp)",
            transport_type
        ));
    }

    // flow работает только с TCP (без транспорта)
    let effective_flow = if !transport_type.is_empty() && transport_type != "tcp" {
        String::new()
    } else {
        flow
    };

    let alpn_raw = percent_decode(params.get("alpn").unwrap_or(&""));
    let alpn: Vec<String> = if alpn_raw.is_empty() {
        Vec::new()
    } else {
        alpn_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };

    Ok(VlessParams {
        uuid: uuid.to_string(),
        host: clean_host.to_string(),
        port,
        security,
        sni: params.get("sni").unwrap_or(&"").to_string(),
        fingerprint: params.get("fp").unwrap_or(&"chrome").to_string(),
        public_key: params.get("pbk").unwrap_or(&"").to_string(),
        short_id: params.get("sid").unwrap_or(&"").to_string(),
        flow: effective_flow,
        name,
        transport_type,
        transport_path: percent_decode(params.get("path").unwrap_or(&"")),
        transport_host: percent_decode(params.get("host").unwrap_or(&"")),
        service_name: percent_decode(params.get("serviceName").unwrap_or(&"")),
        alpn,
    })
}

/// Запись — сетевой адрес (CIDR или IP) или доменное имя
pub(crate) fn is_network_entry(s: &str) -> bool {
    // CIDR notation (e.g. 10.0.0.0/8, 2001:db8::/32)
    if let Some(slash) = s.find('/') {
        return s[..slash].parse::<IpAddr>().is_ok();
    }
    // Bare IP address
    s.parse::<IpAddr>().is_ok()
}

/// Валидация доменного имени / суффикса для маршрутизации.
/// Допускает как полные домены (example.ru), так и TLD-суффиксы (ru)
/// — после нормализации `.ru` → `ru`, sing-box domain_suffix корректно
/// матчит все домены в этой зоне.
pub(crate) fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Нормализация записи маршрута: извлекает домен из URL, убирает trailing slash/пробелы,
/// убирает ведущую точку (.ru → ru) для корректной работы domain_suffix.
pub(crate) fn normalize_entry(s: &str) -> String {
    let s = s.trim();
    // Если пользователь вставил URL вида https://example.com/path — извлекаем хост
    let s = if let Some(rest) = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")) {
        let host = rest.split('/').next().unwrap_or(rest);
        // Убираем порт если есть
        host.split(':').next().unwrap_or(host).to_lowercase()
    } else {
        s.trim_end_matches('/').to_lowercase()
    };
    // *.ru → ru, .ru → ru — sing-box domain_suffix и так работает как суффикс-матч
    let s = s.strip_prefix("*.").or_else(|| s.strip_prefix('.')).unwrap_or(&s).to_string();
    s
}

/// Строит sing-box route rules.
/// bypass       — домены/IP мимо VPN (direct)
/// bypass_apps  — процессы мимо VPN (direct)
/// server_host  — хост VPN-сервера (IP или домен), исключается из TUN
/// Всё остальное идёт через proxy (final=proxy).
fn build_route(
    bypass: &[String],
    bypass_apps: &[String],
    server_host: &str,
    mode: &VpnMode,
) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();

    // В TUN-режиме sing-box 1.13 требует sniff и hijack-dns как route rules
    if *mode == VpnMode::Tun {
        rules.push(serde_json::json!({ "action": "sniff" }));
        rules.push(serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }));
    }

    // VPN-сервер всегда идёт напрямую (предотвращает петлю в TUN-режиме)
    if *mode == VpnMode::Tun && !server_host.is_empty() && server_host.parse::<IpAddr>().is_err() {
        rules.push(serde_json::json!({ "domain": [server_host], "outbound": "direct" }));
    }

    // bypass sites → direct (с валидацией доменов по RFC 1035)
    let norm_bypass: Vec<String> = bypass.iter().map(|s| normalize_entry(s)).collect();
    if !norm_bypass.is_empty() {
        let (nets, domains): (Vec<_>, Vec<_>) =
            norm_bypass.iter().partition(|s| is_network_entry(s));
        let valid_domains: Vec<_> = domains
            .into_iter()
            .filter(|d| is_valid_domain(d))
            .collect();
        if !valid_domains.is_empty() {
            rules.push(serde_json::json!({ "outbound": "direct", "domain_suffix": valid_domains }));
        }
        if !nets.is_empty() {
            rules.push(serde_json::json!({ "outbound": "direct", "ip_cidr": nets }));
        }
    }

    // bypass apps → direct (process_name)
    let norm_apps: Vec<String> = bypass_apps.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !norm_apps.is_empty() {
        rules.push(serde_json::json!({ "outbound": "direct", "process_name": norm_apps }));
    }

    if *mode == VpnMode::Tun {
        rules.push(serde_json::json!({ "ip_cidr": ["1.1.1.1/32"], "outbound": "direct" }));
        rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));
    }

    serde_json::json!({
        "rules": rules,
        "final": "proxy",
        "auto_detect_interface": true,
        "default_domain_resolver": "dns-direct"
    })
}

/// DNS конфиг. В TUN — полный с bypass-правилами, в Proxy — минимальный для резолва.
fn build_dns(bypass: &[String], server_host: &str, mode: &VpnMode) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();

    if *mode == VpnMode::Tun {
        // DNS для VPN-сервера — всегда через direct (предотвращает петлю резолва)
        if !server_host.is_empty() && server_host.parse::<IpAddr>().is_err() {
            rules.push(serde_json::json!({
                "domain": [server_host],
                "server": "dns-direct"
            }));
        }

        if !bypass.is_empty() {
            let norm: Vec<String> = bypass.iter().map(|s| normalize_entry(s)).collect();
            let (_, domains): (Vec<_>, Vec<_>) =
                norm.iter().partition(|s| is_network_entry(s));
            let valid_domains: Vec<_> = domains
                .into_iter()
                .filter(|d| is_valid_domain(d))
                .collect();
            if !valid_domains.is_empty() {
                rules.push(serde_json::json!({
                    "domain_suffix": valid_domains,
                    "server": "dns-direct"
                }));
            }
        }
    }

    // dns-vpn: через VPN (8.8.8.8 через proxy outbound)
    // dns-direct: UDP 1.1.1.1 без detour — трафик к 1.1.1.1 исключён из TUN
    // через route_exclude_address и route rule → direct outbound.
    // detour: "direct" нельзя (sing-box 1.13: "empty direct outbound"),
    // type: "local" нельзя (петля: system DNS → TUN → sing-box → system DNS).
    serde_json::json!({
        "servers": [
            {
                "type": "udp",
                "tag": "dns-vpn",
                "server": "8.8.8.8",
                "server_port": 53,
                "detour": "proxy"
            },
            {
                "type": "udp",
                "tag": "dns-direct",
                "server": "1.1.1.1",
                "server_port": 53
            }
        ],
        "rules": rules,
        "strategy": "ipv4_only",
        "final": "dns-vpn",
        "independent_cache": true
    })
}

pub fn generate_singbox_config(
    p: &VlessParams,
    bypass: &[String],
    bypass_apps: &[String],
    mode: &VpnMode,
    proxy_port: u16,
    clash_secret: &str,
) -> serde_json::Value {
    let tls = match p.security.as_str() {
        "reality" => serde_json::json!({
            "enabled": true,
            "server_name": p.sni,
            "utls": { "enabled": true, "fingerprint": p.fingerprint },
            "reality": {
                "enabled": true,
                "public_key": p.public_key,
                "short_id": p.short_id
            }
        }),
        "tls" => {
            let mut tls_obj = serde_json::json!({
                "enabled": true,
                "server_name": p.sni,
                "utls": { "enabled": !p.fingerprint.is_empty(), "fingerprint": p.fingerprint }
            });
            if !p.alpn.is_empty() {
                tls_obj["alpn"] = serde_json::json!(p.alpn);
            }
            tls_obj
        },
        _ => serde_json::json!({ "enabled": false }),
    };

    let mut outbound = serde_json::json!({
        "type": "vless",
        "tag": "proxy",
        "server": p.host,
        "server_port": p.port,
        "uuid": p.uuid,
        "tls": tls
    });
    if !p.flow.is_empty() {
        outbound["flow"] = serde_json::Value::String(p.flow.clone());
    }
    outbound["packet_encoding"] = serde_json::Value::String("xudp".into());

    // Transport
    let transport = match p.transport_type.as_str() {
        "ws" => {
            let mut t = serde_json::json!({ "type": "ws" });
            if !p.transport_path.is_empty() {
                t["path"] = serde_json::Value::String(p.transport_path.clone());
            }
            if !p.transport_host.is_empty() {
                t["headers"] = serde_json::json!({ "Host": p.transport_host });
            }
            Some(t)
        }
        "http" => {
            let mut t = serde_json::json!({ "type": "http" });
            if !p.transport_path.is_empty() {
                t["path"] = serde_json::Value::String(p.transport_path.clone());
            }
            if !p.transport_host.is_empty() {
                let hosts: Vec<&str> = p.transport_host.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
                t["host"] = serde_json::json!(hosts);
            }
            Some(t)
        }
        "grpc" => {
            let mut t = serde_json::json!({ "type": "grpc" });
            if !p.service_name.is_empty() {
                t["service_name"] = serde_json::Value::String(p.service_name.clone());
            }
            Some(t)
        }
        "quic" => Some(serde_json::json!({ "type": "quic" })),
        "httpupgrade" => {
            let mut t = serde_json::json!({ "type": "httpupgrade" });
            if !p.transport_path.is_empty() {
                t["path"] = serde_json::Value::String(p.transport_path.clone());
            }
            if !p.transport_host.is_empty() {
                t["host"] = serde_json::Value::String(p.transport_host.clone());
            }
            Some(t)
        }
        "tcp" | "" => None, // raw TCP — no transport section
        _ => None,
    };
    if let Some(t) = transport {
        outbound["transport"] = t;
    }

    let inbound = match mode {
        VpnMode::Proxy => serde_json::json!([{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": proxy_port
        }]),
        VpnMode::Tun => {
            // IPv4 → /32, IPv6 → /128, домен → пропускаем
            let mut exclude = vec!["1.1.1.1/32".to_string(), "2000::/3".to_string()];
            if let Ok(ip) = p.host.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(_) => exclude.insert(0, format!("{}/32", p.host)),
                    IpAddr::V6(_) => exclude.insert(0, format!("{}/128", p.host)),
                }
            }
            serde_json::json!([{
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "E13VPN",
                "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
                "mtu": 1500,
                "auto_route": true,
                "strict_route": false,
                "stack": "gvisor",
                "route_exclude_address": exclude
            }])
        },
    };

    let server_host = p.host.to_lowercase();
    let config = serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "dns": build_dns(bypass, &server_host, mode),
        "inbounds": inbound,
        "outbounds": [
            outbound,
            { "type": "direct", "tag": "direct" }
        ],
        "route": build_route(bypass, bypass_apps, &server_host, mode),
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": clash_secret
            }
        }
    });

    // clash_api в proxy-режиме тоже полезно для индикатора скорости
    config
}

/// Нормализует и валидирует запись маршрута.
/// Возвращает (нормализованное_значение, валидно_ли).
pub fn validate_route_entry(raw: &str) -> (String, bool) {
    let norm = normalize_entry(raw);
    let valid = !norm.is_empty() && (is_network_entry(&norm) || is_valid_domain(&norm));
    (norm, valid)
}

/// HTTP-прокси на 127.0.0.1:{port}
pub fn set_system_proxy(enable: bool, port: u16) -> Result<(), String> {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let settings = hkcu
            .open_subkey_with_flags(path, KEY_WRITE)
            .map_err(|e| e.to_string())?;

        if enable {
            settings
                .set_value("ProxyEnable", &1u32)
                .map_err(|e| e.to_string())?;
            settings
                .set_value("ProxyServer", &format!("127.0.0.1:{}", port))
                .map_err(|e| e.to_string())?;
        } else {
            settings
                .set_value("ProxyEnable", &0u32)
                .map_err(|e| e.to_string())?;
        }

        // Уведомляем WinINet — без этого Chrome/Edge не подхватывают смену прокси
        unsafe {
            use windows_sys::Win32::Networking::WinInet::{
                InternetSetOptionA, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
            };
            InternetSetOptionA(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
            InternetSetOptionA(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
    }
    Ok(())
}
