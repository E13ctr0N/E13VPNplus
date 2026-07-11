//! Генератор Xray-config для vless+xhttp/splithttp.
//!
//! sing-box не поддерживает XHTTP/SplitHTTP транспорты (см. vpn.rs ALLOWED_TRANSPORT),
//! поэтому для них используется Xray-core как второе ядро. Этот модуль строит JSON,
//! который Xray понимает: его формат отличается от sing-box.
//!
//! Особенности относительно sing-box:
//! - Xray не имеет `mixed`-инбаунда — раздельные HTTP и SOCKS. Windows system proxy
//!   ходит в HTTP (proxy_port), tun2socks ходит в SOCKS (proxy_port + 1).
//! - bypass_apps (per-process routing) не поддерживается Xray — параметр принимается
//!   для совместимости сигнатуры с sing-box, но реально игнорируется (вызывающий код
//!   логирует warn, если список не пуст).
//! - TUN-инбаунда в Xray нет. Для mode=Tun в lib.rs поверх Xray запускается tun2socks,
//!   но конфиг здесь всегда генерирует HTTP+SOCKS — tun2socks соединяется с SOCKS
//!   как внешний SOCKS5-клиент.

use crate::vpn::{
    is_network_entry, is_valid_domain, normalize_entry, RoutePolicy, VlessParams, VpnMode,
};

/// Строит Xray JSON конфиг для vless+xhttp/splithttp.
///
/// `proxy_port` — HTTP inbound (system proxy).
/// SOCKS inbound слушает на `proxy_port + 1` — используется tun2socks для TUN-режима.
/// В Proxy-режиме SOCKS тоже открыт, но никем не используется (минимальный оверхед).
pub fn generate_xray_config(
    p: &VlessParams,
    bypass: &[String],
    _bypass_apps: &[String], // Xray не умеет per-process; игнорируется здесь, вызывающий код логирует warn
    _mode: &VpnMode,         // конфиг одинаковый для Proxy/Tun — TUN оркеструется внешним tun2socks
    route_policy: &RoutePolicy,
    proxy_port: u16,
) -> serde_json::Value {
    // ===== streamSettings.security =====
    let security = match p.security.as_str() {
        "reality" => "reality",
        "tls" => "tls",
        _ => "none",
    };

    // ===== streamSettings (reality/tls settings + xhttp settings) =====
    let mut stream_settings = serde_json::json!({
        "network": "xhttp",
        "security": security,
    });

    if security == "reality" {
        let mut reality = serde_json::json!({
            "serverName": p.sni,
            "fingerprint": if p.fingerprint.is_empty() { "chrome".to_string() } else { p.fingerprint.clone() },
            "publicKey": p.public_key,
        });
        if !p.short_id.is_empty() {
            reality["shortId"] = serde_json::Value::String(p.short_id.clone());
        }
        stream_settings["realitySettings"] = reality;
    } else if security == "tls" {
        let mut tls = serde_json::json!({
            "serverName": p.sni,
        });
        if !p.fingerprint.is_empty() {
            tls["fingerprint"] = serde_json::Value::String(p.fingerprint.clone());
        }
        if !p.alpn.is_empty() {
            tls["alpn"] = serde_json::json!(p.alpn);
        }
        stream_settings["tlsSettings"] = tls;
    }

    // XHTTP-специфичные настройки.
    // Xray-core 1.8.10+ использует ключ "xhttpSettings" (он же покрывает splithttp).
    let mut xhttp_settings = serde_json::json!({
        "mode": "auto", // auto выберет packet-up/stream-up/stream-one по серверу
    });
    if !p.transport_host.is_empty() {
        xhttp_settings["host"] = serde_json::Value::String(p.transport_host.clone());
    }
    if !p.transport_path.is_empty() {
        xhttp_settings["path"] = serde_json::Value::String(p.transport_path.clone());
    }
    stream_settings["xhttpSettings"] = xhttp_settings;

    // ===== outbound: vless =====
    let mut user = serde_json::json!({
        "id": p.uuid,
        "encryption": "none",
    });
    if !p.flow.is_empty() {
        user["flow"] = serde_json::Value::String(p.flow.clone());
    }

    let proxy_outbound = serde_json::json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": p.host,
                "port": p.port,
                "users": [user],
            }]
        },
        "streamSettings": stream_settings,
    });

    // ===== inbounds =====
    let inbounds = serde_json::json!([
        {
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": proxy_port,
            "protocol": "http",
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
        },
        {
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": proxy_port.saturating_add(1),
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
        }
    ]);

    // ===== routing rules: bypass → direct =====
    let mut routing_rules: Vec<serde_json::Value> = Vec::new();
    let selected_outbound = match route_policy {
        RoutePolicy::Bypass => "direct",
        RoutePolicy::OnlyVpn => "proxy",
    };

    // VPN-сервер всегда мимо (избегаем петли в TUN-режиме через tun2socks).
    if !p.host.is_empty() {
        if p.host.parse::<std::net::IpAddr>().is_ok() {
            routing_rules.push(serde_json::json!({
                "type": "field",
                "ip": [format!("{}/32", p.host)],
                "outboundTag": "direct"
            }));
        } else {
            routing_rules.push(serde_json::json!({
                "type": "field",
                "domain": [format!("domain:{}", p.host)],
                "outboundTag": "direct"
            }));
        }
    }

    // Пользовательские bypass-записи (нормализованные).
    let norm_bypass: Vec<String> = bypass.iter().map(|s| normalize_entry(s)).collect();
    let (nets, domains): (Vec<_>, Vec<_>) = norm_bypass.iter().partition(|s| is_network_entry(s));
    let valid_domains: Vec<String> = domains
        .into_iter()
        .filter(|d| is_valid_domain(d))
        .map(|d| format!("domain:{}", d))
        .collect();
    let ip_nets: Vec<String> = nets.into_iter().cloned().collect();

    if !valid_domains.is_empty() {
        routing_rules.push(serde_json::json!({
            "type": "field",
            "domain": valid_domains,
            "outboundTag": selected_outbound
        }));
    }
    if !ip_nets.is_empty() {
        routing_rules.push(serde_json::json!({
            "type": "field",
            "ip": ip_nets,
            "outboundTag": selected_outbound
        }));
    }

    // Приватные сети — всегда direct (RFC 1918, loopback, link-local).
    // Явный CIDR-список вместо "geoip:private" — чтобы не требовать geoip.dat
    // (~10 МБ файл из v2fly-rules-dat, который пришлось бы бандлить отдельно).
    routing_rules.push(serde_json::json!({
        "type": "field",
        "ip": [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10"
        ],
        "outboundTag": "direct"
    }));

    if *route_policy == RoutePolicy::OnlyVpn {
        routing_rules.push(serde_json::json!({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": "direct"
        }));
    }

    // ===== собираем итоговый конфиг =====
    serde_json::json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound,
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": routing_rules
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::parse_vless_uri;

    #[test]
    fn xhttp_reality_config_has_required_fields() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443\
                   ?type=xhttp&security=reality&pbk=testpbk&sid=abcd&sni=www.google.com\
                   &fp=chrome&host=example.com&path=/ray#test";
        let p = parse_vless_uri(uri).expect("parse xhttp URI");
        assert_eq!(p.transport_type, "xhttp");

        let cfg = generate_xray_config(&p, &[], &[], &VpnMode::Proxy, &RoutePolicy::Bypass, 10800);
        let ob = &cfg["outbounds"][0];
        assert_eq!(ob["protocol"], "vless");
        assert_eq!(ob["streamSettings"]["network"], "xhttp");
        assert_eq!(ob["streamSettings"]["security"], "reality");
        assert_eq!(
            ob["streamSettings"]["realitySettings"]["publicKey"],
            "testpbk"
        );
        assert_eq!(ob["streamSettings"]["xhttpSettings"]["path"], "/ray");
        assert_eq!(cfg["inbounds"][0]["port"], 10800);
        assert_eq!(cfg["inbounds"][1]["port"], 10801);
    }

    #[test]
    fn xray_socks_inbound_can_use_last_dynamic_port() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443\
                   ?type=xhttp&security=reality&pbk=testpbk&sid=abcd&sni=www.google.com#test";
        let p = parse_vless_uri(uri).expect("parse xhttp URI");

        let cfg = generate_xray_config(&p, &[], &[], &VpnMode::Proxy, &RoutePolicy::Bypass, 65534);
        assert_eq!(cfg["inbounds"][0]["port"], 65534);
        assert_eq!(cfg["inbounds"][1]["port"], 65535);
    }

    #[test]
    fn splithttp_maps_to_xhttp_network() {
        // splithttp в URI → Xray engine → сеть в Xray всё равно "xhttp"
        // (splithttp в Xray 1.8.10+ = xhttp, это единый транспорт).
        let uri = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443\
                   ?type=splithttp&security=tls&sni=foo.com#t";
        let p = parse_vless_uri(uri).expect("parse splithttp URI");
        assert_eq!(p.transport_type, "splithttp");

        let cfg = generate_xray_config(&p, &[], &[], &VpnMode::Proxy, &RoutePolicy::Bypass, 10800);
        assert_eq!(cfg["outbounds"][0]["streamSettings"]["network"], "xhttp");
    }

    #[test]
    fn bypass_rules_added() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443\
                   ?type=xhttp&security=reality&pbk=x#t";
        let p = parse_vless_uri(uri).unwrap();
        let bypass = vec!["ru".to_string(), "10.0.0.0/8".to_string()];
        let cfg = generate_xray_config(
            &p,
            &bypass,
            &[],
            &VpnMode::Proxy,
            &RoutePolicy::Bypass,
            10800,
        );
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // server IP + domain bypass + ip bypass + geoip:private
        assert!(rules.len() >= 4);
    }

    #[test]
    fn only_vpn_rules_proxy_selected_and_catch_all_direct() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443\
                   ?type=xhttp&security=reality&pbk=x#t";
        let p = parse_vless_uri(uri).unwrap();
        let selected = vec!["example.com".to_string(), "203.0.113.0/24".to_string()];
        let cfg = generate_xray_config(
            &p,
            &selected,
            &[],
            &VpnMode::Proxy,
            &RoutePolicy::OnlyVpn,
            10800,
        );
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|rule| {
            rule["domain"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|d| d == "domain:example.com"))
                && rule["outboundTag"] == "proxy"
        }));
        assert!(rules.iter().any(|rule| {
            rule["ip"]
                .as_array()
                .is_some_and(|nets| nets.iter().any(|net| net == "203.0.113.0/24"))
                && rule["outboundTag"] == "proxy"
        }));
        assert!(rules
            .iter()
            .any(|rule| { rule["network"] == "tcp,udp" && rule["outboundTag"] == "direct" }));
    }

    #[cfg(windows)]
    #[test]
    fn generated_xhttp_config_is_accepted_by_bundled_xray() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=reality&pbk=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&sid=abcd&sni=example.com#xhttp";
        let params = parse_vless_uri(uri).expect("parse xhttp URI");
        let cfg = generate_xray_config(
            &params,
            &[],
            &[],
            &VpnMode::Proxy,
            &RoutePolicy::Bypass,
            2080,
        );
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join("xray-x86_64-pc-windows-msvc.exe");
        assert!(binary.exists(), "bundled Xray binary is missing");

        let config_path = std::env::temp_dir().join(format!(
            "e13vpn-xray-config-check-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&cfg).expect("serialize Xray config"),
        )
        .expect("write Xray config");
        let output = std::process::Command::new(binary)
            .args(["run", "-test", "-c"])
            .arg(&config_path)
            .output()
            .expect("run Xray config check");
        let _ = std::fs::remove_file(&config_path);

        assert!(
            output.status.success(),
            "Xray rejected generated config. stdout: {} stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
