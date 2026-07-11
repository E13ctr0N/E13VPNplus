use base64::Engine;
use serde::Serialize;
use std::collections::HashSet;

pub const MAX_SUBSCRIPTION_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionImport {
    pub configs: Vec<String>,
    pub skipped: usize,
}

pub fn parse_subscription_body(body: &str) -> Result<SubscriptionImport, String> {
    if body.len() > MAX_SUBSCRIPTION_BODY_BYTES {
        return Err("subscription response too large".into());
    }

    let trimmed = body.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let mut best = parse_plain_subscription(trimmed);
    if !best.configs.is_empty() {
        return Ok(best);
    }

    for decoded in decode_subscription_candidates(trimmed) {
        let parsed = parse_plain_subscription(&decoded);
        if !parsed.configs.is_empty() {
            return Ok(parsed);
        }
        if parsed.skipped > best.skipped {
            best = parsed;
        }
    }

    Ok(best)
}

fn parse_plain_subscription(body: &str) -> SubscriptionImport {
    let mut configs = Vec::new();
    let mut seen = HashSet::new();
    let mut skipped = 0;

    for line in body.lines() {
        let uri = line.trim();
        if uri.is_empty() || uri.starts_with('#') {
            continue;
        }
        if !is_supported_proxy_uri(uri) {
            skipped += 1;
            continue;
        }
        if crate::vpn::parse_proxy_uri(uri).is_err() {
            skipped += 1;
            continue;
        }
        if seen.insert(uri.to_string()) {
            configs.push(uri.to_string());
        }
    }

    SubscriptionImport { configs, skipped }
}

fn is_supported_proxy_uri(uri: &str) -> bool {
    uri.starts_with("vless://")
        || uri.starts_with("naive+https://")
        || uri.starts_with("naive+quic://")
}

fn decode_subscription_candidates(input: &str) -> Vec<String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Vec::new();
    }

    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for engine in engines {
        if let Ok(bytes) = engine.decode(&compact) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                if seen.insert(decoded.clone()) {
                    candidates.push(decoded);
                }
            }
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn vless(name: &str) -> String {
        format!("vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&pbk=key&sid=id#{}", name)
    }

    #[test]
    fn parses_plain_uri_list() {
        let first = vless("one");
        let second = "naive+https://user:pass@example.com#two".to_string();
        let input = format!("{first}\r\n{second}\n");

        let result = parse_subscription_body(&input).expect("parse subscription");

        assert_eq!(result.configs, vec![first, second]);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn parses_base64_encoded_uri_list() {
        let first = vless("one");
        let second = vless("two");
        let body = format!("{first}\n{second}\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);

        let result = parse_subscription_body(&encoded).expect("parse subscription");

        assert_eq!(result.configs, vec![first, second]);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn parses_url_safe_base64_without_padding() {
        let first = vless("one");
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&first);

        let result = parse_subscription_body(&encoded).expect("parse subscription");

        assert_eq!(result.configs, vec![first]);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn skips_unsupported_subscription_links() {
        let first = vless("one");
        let input = format!("{first}\nvmess://abc\ntrojan://secret@example.com:443\nss://abc\n");

        let result = parse_subscription_body(&input).expect("parse subscription");

        assert_eq!(result.configs, vec![first]);
        assert_eq!(result.skipped, 3);
    }

    #[test]
    fn rejects_body_over_size_limit() {
        let input = "a".repeat(MAX_SUBSCRIPTION_BODY_BYTES + 1);

        let err = parse_subscription_body(&input).expect_err("reject large body");

        assert!(err.contains("too large"));
    }
}
