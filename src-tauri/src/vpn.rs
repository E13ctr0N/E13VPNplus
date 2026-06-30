use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum VpnMode {
    Proxy,
    Tun,
}

impl VpnMode {
    pub fn from_str(s: &str) -> Self {
        if s == "tun" {
            VpnMode::Tun
        } else {
            VpnMode::Proxy
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoutePolicy {
    Bypass,
    OnlyVpn,
}

impl RoutePolicy {
    pub fn from_str(s: &str) -> Self {
        if s == "only_vpn" {
            RoutePolicy::OnlyVpn
        } else {
            RoutePolicy::Bypass
        }
    }

    fn selected_outbound(&self) -> &'static str {
        match self {
            RoutePolicy::Bypass => "direct",
            RoutePolicy::OnlyVpn => "proxy",
        }
    }

    fn final_outbound(&self) -> &'static str {
        match self {
            RoutePolicy::Bypass => "proxy",
            RoutePolicy::OnlyVpn => "direct",
        }
    }

    fn selected_dns_server(&self) -> &'static str {
        match self {
            RoutePolicy::Bypass => "dns-direct",
            RoutePolicy::OnlyVpn => "dns-vpn",
        }
    }

    fn final_dns_server(&self) -> &'static str {
        match self {
            RoutePolicy::Bypass => "dns-vpn",
            RoutePolicy::OnlyVpn => "dns-direct",
        }
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

#[derive(Debug, Clone)]
pub struct NaiveParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    #[allow(dead_code)]
    pub name: String,
    pub quic: bool,
    pub tls_server_name: String,
    pub insecure_concurrency: Option<u16>,
    pub extra_headers: HashMap<String, String>,
    pub udp_over_tcp: bool,
    pub quic_congestion_control: String,
}

#[derive(Debug, Clone)]
pub enum ProxyParams {
    Vless(VlessParams),
    Naive(NaiveParams),
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

impl ProxyParams {
    pub fn engine(&self) -> VpnEngine {
        match self {
            ProxyParams::Vless(params) => params.engine(),
            ProxyParams::Naive(_) => VpnEngine::SingBox,
        }
    }

    pub fn server_host(&self) -> &str {
        match self {
            ProxyParams::Vless(params) => &params.host,
            ProxyParams::Naive(params) => &params.host,
        }
    }

    pub fn requires_libcronet(&self) -> bool {
        matches!(self, ProxyParams::Naive(_))
    }

    pub fn as_vless(&self) -> Option<&VlessParams> {
        match self {
            ProxyParams::Vless(params) => Some(params),
            ProxyParams::Naive(_) => None,
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
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(part, &len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
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
    "",
    "tcp",
    "ws",
    "http",
    "grpc",
    "quic",
    "httpupgrade",
    "xhttp",
    "splithttp",
];
#[cfg(not(feature = "xhttp"))]
const ALLOWED_TRANSPORT: &[&str] = &["", "tcp", "ws", "http", "grpc", "quic", "httpupgrade"];

pub fn parse_proxy_uri(uri: &str) -> Result<ProxyParams, String> {
    let uri = uri.trim();
    if uri.starts_with("vless://") {
        return parse_vless_uri(uri).map(ProxyParams::Vless);
    }
    if uri.starts_with("naive+https://") || uri.starts_with("naive+quic://") {
        return parse_naive_uri(uri).map(ProxyParams::Naive);
    }
    Err("неподдерживаемый URI: ожидается vless://, naive+https:// или naive+quic://".into())
}

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
    let (uuid, rest) = s.split_once('@').ok_or("неверный формат: нет @")?;

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
        return Err(format!(
            "неверный хост: '{}'",
            if host.len() > 100 { &host[..100] } else { host }
        ));
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
        alpn_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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

fn parse_bool_query(value: Option<&&str>) -> bool {
    value
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn parse_host_port_default(hostport: &str, default_port: u16) -> Result<(String, u16), String> {
    if hostport.is_empty() {
        return Err("неверный формат: пустой хост".into());
    }

    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest.find(']').ok_or("неверный IPv6 host: нет ]")?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if let Some(port_s) = after.strip_prefix(':') {
            port_s
                .parse::<u16>()
                .map_err(|_| format!("неверный порт: {port_s}"))?
        } else if after.is_empty() {
            default_port
        } else {
            return Err("неверный host:port".into());
        };
        (host.to_string(), port)
    } else if let Some((host, port_s)) = hostport.rsplit_once(':') {
        if port_s.chars().all(|c| c.is_ascii_digit()) {
            (
                host.to_string(),
                port_s
                    .parse::<u16>()
                    .map_err(|_| format!("неверный порт: {port_s}"))?,
            )
        } else {
            (hostport.to_string(), default_port)
        }
    } else {
        (hostport.to_string(), default_port)
    };

    let clean_host = host.trim_matches(|c| c == '[' || c == ']').to_string();
    if clean_host.parse::<IpAddr>().is_err() && !is_valid_domain(&clean_host) {
        return Err(format!(
            "неверный хост: '{}'",
            if clean_host.len() > 100 {
                &clean_host[..100]
            } else {
                &clean_host
            }
        ));
    }
    if port == 0 {
        return Err("порт не может быть 0".into());
    }

    Ok((clean_host, port))
}

fn parse_naive_extra_headers(raw: &str) -> Result<HashMap<String, String>, String> {
    let decoded = percent_decode(raw);
    let mut headers = HashMap::new();
    if decoded.trim().is_empty() {
        return Ok(headers);
    }

    for line in decoded.split("\r\n") {
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or("неверный naive extra-headers: ожидается Header:Value")?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
        {
            return Err("неверный naive extra-headers: некорректное имя header".into());
        }
        headers.insert(name.to_string(), value.trim().to_string());
    }

    Ok(headers)
}

fn parse_naive_uri(uri: &str) -> Result<NaiveParams, String> {
    let uri = uri.trim();
    if uri.len() > 10240 {
        return Err("URI слишком длинный (макс. 10 КБ)".into());
    }

    let (scheme, rest) = uri
        .split_once("://")
        .ok_or("неверный naive URI: нет scheme")?;
    let quic = match scheme {
        "naive+https" => false,
        "naive+quic" => true,
        _ => return Err("неподдерживаемый naive scheme".into()),
    };

    let (rest, name) = if let Some(idx) = rest.rfind('#') {
        (&rest[..idx], percent_decode(&rest[idx + 1..]))
    } else {
        (rest, "без имени".into())
    };
    let (authority, query) = if let Some(idx) = rest.find('?') {
        (&rest[..idx], &rest[idx + 1..])
    } else {
        (rest, "")
    };

    let (userinfo, hostport) = if let Some((userinfo, hostport)) = authority.rsplit_once('@') {
        (Some(userinfo), hostport)
    } else {
        (None, authority)
    };
    let (username, password) = match userinfo {
        Some(raw) => {
            let (user, pass) = raw.split_once(':').unwrap_or((raw, ""));
            (percent_decode(user), percent_decode(pass))
        }
        None => (String::new(), String::new()),
    };
    let (host, port) = parse_host_port_default(hostport, 443)?;

    let params: HashMap<&str, &str> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();
    let tls_server_name = params
        .get("sni")
        .or_else(|| params.get("server_name"))
        .map(|v| percent_decode(v))
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| host.clone());
    let insecure_concurrency = params
        .get("insecure-concurrency")
        .or_else(|| params.get("insecure_concurrency"))
        .map(|v| {
            v.parse::<u16>()
                .map_err(|_| format!("неверный insecure_concurrency: {v}"))
        })
        .transpose()?;
    let extra_headers = params
        .get("extra-headers")
        .or_else(|| params.get("extra_headers"))
        .map(|v| parse_naive_extra_headers(v))
        .transpose()?
        .unwrap_or_default();
    let udp_over_tcp = parse_bool_query(
        params
            .get("udp-over-tcp")
            .or_else(|| params.get("udp_over_tcp"))
            .or_else(|| params.get("uot")),
    );
    let quic_congestion_control = params
        .get("quic-congestion-control")
        .or_else(|| params.get("quic_congestion_control"))
        .map(|v| percent_decode(v))
        .unwrap_or_default();

    Ok(NaiveParams {
        host,
        port,
        username,
        password,
        name,
        quic,
        tls_server_name,
        insecure_concurrency,
        extra_headers,
        udp_over_tcp,
        quic_congestion_control,
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
    let s = if let Some(rest) = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
    {
        let host = rest.split('/').next().unwrap_or(rest);
        // Убираем порт если есть
        host.split(':').next().unwrap_or(host).to_lowercase()
    } else {
        s.trim_end_matches('/').to_lowercase()
    };
    // *.ru → ru, .ru → ru — sing-box domain_suffix и так работает как суффикс-матч
    let s = s
        .strip_prefix("*.")
        .or_else(|| s.strip_prefix('.'))
        .unwrap_or(&s)
        .to_string();
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
    route_policy: &RoutePolicy,
    block_udp: bool,
) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();

    // В TUN-режиме sing-box 1.13 требует sniff и hijack-dns как route rules
    if *mode == VpnMode::Tun {
        rules.push(serde_json::json!({ "action": "sniff" }));
        rules.push(serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }));
        if block_udp {
            rules.push(serde_json::json!({ "network": "udp", "outbound": "block" }));
        }
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
        let valid_domains: Vec<_> = domains.into_iter().filter(|d| is_valid_domain(d)).collect();
        if !valid_domains.is_empty() {
            rules.push(serde_json::json!({
                "outbound": route_policy.selected_outbound(),
                "domain_suffix": valid_domains
            }));
        }
        if !nets.is_empty() {
            rules.push(serde_json::json!({
                "outbound": route_policy.selected_outbound(),
                "ip_cidr": nets
            }));
        }
    }

    // bypass apps → direct (process_name)
    let norm_apps: Vec<String> = bypass_apps
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !norm_apps.is_empty() {
        rules.push(serde_json::json!({
            "outbound": route_policy.selected_outbound(),
            "process_name": norm_apps
        }));
    }

    if *mode == VpnMode::Tun {
        rules.push(serde_json::json!({ "ip_cidr": ["1.1.1.1/32"], "outbound": "direct" }));
        rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));
    }

    serde_json::json!({
        "rules": rules,
        "final": route_policy.final_outbound(),
        "auto_detect_interface": true,
        "default_domain_resolver": "dns-direct"
    })
}

/// DNS конфиг. В TUN — полный с bypass-правилами, в Proxy — минимальный для резолва.
fn build_dns(
    bypass: &[String],
    server_host: &str,
    mode: &VpnMode,
    route_policy: &RoutePolicy,
    proxy_dns_over_tcp: bool,
) -> serde_json::Value {
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
            let (_, domains): (Vec<_>, Vec<_>) = norm.iter().partition(|s| is_network_entry(s));
            let valid_domains: Vec<_> =
                domains.into_iter().filter(|d| is_valid_domain(d)).collect();
            if !valid_domains.is_empty() {
                rules.push(serde_json::json!({
                    "domain_suffix": valid_domains,
                    "server": route_policy.selected_dns_server()
                }));
            }
        }
    }

    // dns-vpn: через VPN. Для Naive/TUN используем DoT, чтобы не требовать UoT на сервере.
    // dns-direct: UDP 1.1.1.1 без detour — трафик к 1.1.1.1 исключён из TUN
    // через route_exclude_address и route rule → direct outbound.
    // detour: "direct" нельзя (sing-box 1.13: "empty direct outbound"),
    // type: "local" нельзя (петля: system DNS → TUN → sing-box → system DNS).
    let dns_vpn = if proxy_dns_over_tcp {
        serde_json::json!({
            "type": "tls",
            "tag": "dns-vpn",
            "server": "8.8.8.8",
            "server_port": 853,
            "detour": "proxy",
            "tls": {
                "server_name": "dns.google"
            }
        })
    } else {
        serde_json::json!({
            "type": "udp",
            "tag": "dns-vpn",
            "server": "8.8.8.8",
            "server_port": 53,
            "detour": "proxy"
        })
    };
    serde_json::json!({
        "servers": [
            dns_vpn,
            {
                "type": "udp",
                "tag": "dns-direct",
                "server": "1.1.1.1",
                "server_port": 53
            }
        ],
        "rules": rules,
        "strategy": "ipv4_only",
        "final": route_policy.final_dns_server(),
        "independent_cache": true
    })
}

fn build_tun_route_exclude_address(server_host: &str) -> Vec<String> {
    let mut exclude = vec!["1.1.1.1/32".to_string(), "2000::/3".to_string()];
    if let Ok(ip) = server_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(_) => exclude.insert(0, format!("{server_host}/32")),
            IpAddr::V6(_) => exclude.insert(0, format!("{server_host}/128")),
        }
    }
    exclude
}

fn build_tun_inbound(server_host: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "E13VPN",
        "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
        "mtu": 1500,
        "auto_route": true,
        "strict_route": false,
        "stack": "gvisor",
        "route_exclude_address": build_tun_route_exclude_address(server_host)
    })
}

fn build_vless_outbound(p: &VlessParams) -> serde_json::Value {
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
        }
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
                let hosts: Vec<&str> = p
                    .transport_host
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
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

    outbound
}

fn build_naive_outbound(p: &NaiveParams, mode: &VpnMode) -> serde_json::Value {
    let mut outbound = serde_json::json!({
        "type": "naive",
        "tag": "proxy",
        "server": p.host,
        "server_port": p.port,
        "tls": {
            "enabled": true,
            "server_name": p.tls_server_name
        }
    });
    if *mode == VpnMode::Tun {
        outbound["domain_resolver"] = serde_json::json!({
            "server": "dns-direct",
            "strategy": "ipv4_only"
        });
    }
    if !p.username.is_empty() {
        outbound["username"] = serde_json::Value::String(p.username.clone());
    }
    if !p.password.is_empty() {
        outbound["password"] = serde_json::Value::String(p.password.clone());
    }
    if let Some(insecure_concurrency) = p.insecure_concurrency {
        outbound["insecure_concurrency"] =
            serde_json::Value::Number(serde_json::Number::from(insecure_concurrency));
    }
    if !p.extra_headers.is_empty() {
        outbound["extra_headers"] = serde_json::json!(p.extra_headers);
    }
    if p.udp_over_tcp {
        outbound["udp_over_tcp"] = serde_json::Value::Bool(true);
    }
    if p.quic {
        outbound["quic"] = serde_json::Value::Bool(true);
    }
    if !p.quic_congestion_control.is_empty() {
        outbound["quic_congestion_control"] =
            serde_json::Value::String(p.quic_congestion_control.clone());
    }

    outbound
}

pub fn generate_singbox_config(
    params: &ProxyParams,
    bypass: &[String],
    bypass_apps: &[String],
    mode: &VpnMode,
    route_policy: &RoutePolicy,
    proxy_port: u16,
    clash_secret: &str,
) -> serde_json::Value {
    let outbound = match params {
        ProxyParams::Vless(p) => build_vless_outbound(p),
        ProxyParams::Naive(p) => build_naive_outbound(p, mode),
    };
    let host = params.server_host();
    let is_naive_tun = matches!(params, ProxyParams::Naive(_)) && *mode == VpnMode::Tun;
    let block_udp =
        matches!(params, ProxyParams::Naive(p) if *mode == VpnMode::Tun && !p.udp_over_tcp);
    let mut outbounds = vec![
        outbound,
        serde_json::json!({ "type": "direct", "tag": "direct" }),
    ];
    if block_udp {
        outbounds.push(serde_json::json!({ "type": "block", "tag": "block" }));
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
            if let Ok(ip) = host.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(_) => exclude.insert(0, format!("{host}/32")),
                    IpAddr::V6(_) => exclude.insert(0, format!("{host}/128")),
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
        }
    };

    let server_host = host.to_lowercase();
    let config = serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "dns": build_dns(bypass, &server_host, mode, route_policy, is_naive_tun),
        "inbounds": inbound,
        "outbounds": outbounds,
        "route": build_route(bypass, bypass_apps, &server_host, mode, route_policy, block_udp),
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
pub fn generate_singbox_xray_tun_router_config(
    bypass: &[String],
    bypass_apps: &[String],
    server_host: &str,
    route_policy: &RoutePolicy,
    xray_socks_port: u16,
) -> serde_json::Value {
    let server_host = server_host.to_lowercase();
    let mut router_bypass_apps = vec![
        "xray.exe".to_string(),
        "xray-x86_64-pc-windows-msvc.exe".to_string(),
    ];
    router_bypass_apps.extend(
        bypass_apps
            .iter()
            .map(|app| app.trim().to_string())
            .filter(|app| !app.is_empty()),
    );

    serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "dns": build_dns(bypass, &server_host, &VpnMode::Tun, route_policy, false),
        "inbounds": [build_tun_inbound(&server_host)],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": xray_socks_port,
                "version": "5"
            },
            { "type": "direct", "tag": "direct" }
        ],
        "route": build_route(bypass, &router_bypass_apps, &server_host, &VpnMode::Tun, route_policy, false)
    })
}

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
            InternetSetOptionA(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionA(
                std::ptr::null(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_tun_router_uses_singbox_tun_and_xray_socks_outbound() {
        let cfg = generate_singbox_xray_tun_router_config(
            &["ru".to_string()],
            &["chrome.exe".to_string()],
            "194.62.248.33",
            &RoutePolicy::Bypass,
            51252,
        );

        assert_eq!(cfg["inbounds"][0]["type"], "tun");
        assert_eq!(cfg["inbounds"][0]["interface_name"], "E13VPN");
        assert_eq!(cfg["outbounds"][0]["type"], "socks");
        assert_eq!(cfg["outbounds"][0]["server"], "127.0.0.1");
        assert_eq!(cfg["outbounds"][0]["server_port"], 51252);
        assert_eq!(cfg["outbounds"][0]["version"], "5");
        assert_eq!(cfg["route"]["final"], "proxy");
    }

    #[test]
    fn xray_tun_router_preserves_route_and_dns_bypass_rules() {
        let cfg = generate_singbox_xray_tun_router_config(
            &["ru".to_string(), "10.0.0.0/8".to_string()],
            &[],
            "example.com",
            &RoutePolicy::Bypass,
            51252,
        );

        let route_rules = cfg["route"]["rules"].as_array().expect("route rules");
        assert!(route_rules.iter().any(|rule| {
            rule["domain_suffix"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|d| d == "ru"))
        }));
        assert!(route_rules.iter().any(|rule| {
            rule["ip_cidr"]
                .as_array()
                .is_some_and(|nets| nets.iter().any(|net| net == "10.0.0.0/8"))
        }));

        let dns_rules = cfg["dns"]["rules"].as_array().expect("dns rules");
        assert!(dns_rules.iter().any(|rule| {
            rule["domain_suffix"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|d| d == "ru"))
                && rule["server"] == "dns-direct"
        }));
    }

    #[test]
    fn xray_tun_router_excludes_server_ip_from_auto_route() {
        let cfg = generate_singbox_xray_tun_router_config(
            &[],
            &[],
            "194.62.248.33",
            &RoutePolicy::Bypass,
            51252,
        );

        let excludes = cfg["inbounds"][0]["route_exclude_address"]
            .as_array()
            .expect("route excludes");
        assert!(excludes.iter().any(|entry| entry == "194.62.248.33/32"));
        assert!(excludes.iter().any(|entry| entry == "1.1.1.1/32"));
    }

    #[test]
    fn only_vpn_policy_routes_selected_entries_to_proxy_and_defaults_direct() {
        let cfg = generate_singbox_xray_tun_router_config(
            &["example.com".to_string(), "203.0.113.0/24".to_string()],
            &["chrome.exe".to_string()],
            "194.62.248.33",
            &RoutePolicy::OnlyVpn,
            51252,
        );

        assert_eq!(cfg["route"]["final"], "direct");
        let rules = cfg["route"]["rules"].as_array().expect("route rules");
        assert!(rules.iter().any(|rule| {
            rule["domain_suffix"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|d| d == "example.com"))
                && rule["outbound"] == "proxy"
        }));
        assert!(rules.iter().any(|rule| {
            rule["ip_cidr"]
                .as_array()
                .is_some_and(|nets| nets.iter().any(|net| net == "203.0.113.0/24"))
                && rule["outbound"] == "proxy"
        }));
        assert!(rules.iter().any(|rule| {
            rule["process_name"]
                .as_array()
                .is_some_and(|apps| apps.iter().any(|app| app == "chrome.exe"))
                && rule["outbound"] == "proxy"
        }));
        assert_eq!(cfg["dns"]["final"], "dns-direct");
    }

    #[test]
    fn parse_naive_https_uri_with_auth_headers_and_name() {
        let params = parse_proxy_uri(
            "naive+https://user:p%40ss@example.com:443?extra-headers=X-Test%3Aone%0D%0AX-Mode%3Atwo#Naive%20Server",
        )
        .expect("parse naive uri");
        let ProxyParams::Naive(naive) = params else {
            panic!("expected naive params");
        };

        assert_eq!(naive.host, "example.com");
        assert_eq!(naive.port, 443);
        assert_eq!(naive.username, "user");
        assert_eq!(naive.password, "p@ss");
        assert!(!naive.quic);
        assert_eq!(naive.name, "Naive Server");
        assert_eq!(
            naive
                .extra_headers
                .get("X-Test")
                .map(std::string::String::as_str),
            Some("one")
        );
        assert_eq!(
            naive
                .extra_headers
                .get("X-Mode")
                .map(std::string::String::as_str),
            Some("two")
        );
    }

    #[test]
    fn parse_naive_quic_uri_defaults_port_and_enables_quic() {
        let params =
            parse_proxy_uri("naive+quic://quic.example.com#QUIC").expect("parse naive uri");
        let ProxyParams::Naive(naive) = params else {
            panic!("expected naive params");
        };

        assert_eq!(naive.host, "quic.example.com");
        assert_eq!(naive.port, 443);
        assert!(naive.quic);
        assert_eq!(naive.name, "QUIC");
    }

    #[test]
    fn naive_singbox_config_uses_naive_outbound_and_tls() {
        let params =
            parse_proxy_uri("naive+https://user:pass@example.com:8443?sni=front.example#naive")
                .expect("parse naive uri");
        let cfg = generate_singbox_config(
            &params,
            &[],
            &[],
            &VpnMode::Proxy,
            &RoutePolicy::Bypass,
            2080,
            "secret",
        );

        let outbound = &cfg["outbounds"][0];
        assert_eq!(outbound["type"], "naive");
        assert_eq!(outbound["tag"], "proxy");
        assert_eq!(outbound["server"], "example.com");
        assert_eq!(outbound["server_port"], 8443);
        assert_eq!(outbound["username"], "user");
        assert_eq!(outbound["password"], "pass");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "front.example");
    }

    #[test]
    fn naive_proxy_config_keeps_udp_over_tcp_disabled_by_default() {
        let params =
            parse_proxy_uri("naive+https://user:pass@example.com#naive").expect("parse naive uri");
        let cfg = generate_singbox_config(
            &params,
            &[],
            &[],
            &VpnMode::Proxy,
            &RoutePolicy::Bypass,
            2080,
            "secret",
        );

        let outbound = &cfg["outbounds"][0];
        assert_eq!(outbound["type"], "naive");
        assert!(outbound.get("udp_over_tcp").is_none());
        assert!(outbound.get("domain_resolver").is_none());
    }

    #[test]
    fn naive_tun_config_without_uot_uses_dot_and_blocks_udp() {
        let params =
            parse_proxy_uri("naive+https://user:pass@example.com#naive").expect("parse naive uri");
        let cfg = generate_singbox_config(
            &params,
            &[],
            &[],
            &VpnMode::Tun,
            &RoutePolicy::Bypass,
            2080,
            "secret",
        );

        let outbound = &cfg["outbounds"][0];
        assert_eq!(outbound["type"], "naive");
        assert!(outbound.get("udp_over_tcp").is_none());
        assert_eq!(outbound["domain_resolver"]["server"], "dns-direct");
        assert_eq!(outbound["domain_resolver"]["strategy"], "ipv4_only");

        let dns_vpn = cfg["dns"]["servers"]
            .as_array()
            .expect("dns servers")
            .iter()
            .find(|server| server["tag"] == "dns-vpn")
            .expect("dns-vpn server");
        assert_eq!(dns_vpn["type"], "tls");
        assert_eq!(dns_vpn["server"], "8.8.8.8");
        assert_eq!(dns_vpn["server_port"], 853);
        assert_eq!(dns_vpn["detour"], "proxy");

        let rules = cfg["route"]["rules"].as_array().expect("route rules");
        assert!(rules
            .iter()
            .any(|rule| rule["network"] == "udp" && rule["outbound"] == "block"));
        assert!(cfg["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .any(|outbound| outbound["tag"] == "block" && outbound["type"] == "block"));
    }

    #[test]
    fn naive_tun_config_with_explicit_uot_enables_udp_and_does_not_block_udp() {
        let params = parse_proxy_uri("naive+https://user:pass@example.com?uot=1#naive")
            .expect("parse naive uri");
        let cfg = generate_singbox_config(
            &params,
            &[],
            &[],
            &VpnMode::Tun,
            &RoutePolicy::Bypass,
            2080,
            "secret",
        );

        let outbound = &cfg["outbounds"][0];
        assert_eq!(outbound["type"], "naive");
        assert_eq!(outbound["udp_over_tcp"], true);

        let rules = cfg["route"]["rules"].as_array().expect("route rules");
        assert!(!rules
            .iter()
            .any(|rule| rule["network"] == "udp" && rule["outbound"] == "block"));
        assert!(!cfg["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .any(|outbound| outbound["tag"] == "block"));
    }
}
