//! Signal extraction helpers for the application inference engine.
//!
//! Pure functions over the domain model: known-service port detection,
//! name slugs, hostname keys, and subnet membership. The engine combines
//! these with the versioned weights in [`super::weights`].

use crate::domain::Asset;

/// Known service combinations: an edge onto one of these ports is
/// evidence that the target runs the named service (roadmap: HTTP →
/// PostgreSQL, HTTP → Redis, Tomcat → Oracle, application → broker).
pub(crate) fn known_service(port: u16) -> Option<&'static str> {
    Some(match port {
        5432 => "PostgreSQL",
        6379 => "Redis",
        3306 => "MySQL",
        1521 => "Oracle",
        27017 => "MongoDB",
        5672 => "message broker (AMQP)",
        9092 => "message broker (Kafka)",
        _ => return None,
    })
}

/// Turn a derived name into a slug: lowercase, non-alphanumeric runs
/// collapsed to single dashes, no leading/trailing dashes.
pub(crate) fn slugify(raw: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in raw.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// The grouping key of a hostname: first DNS label, lowercased, with
/// trailing digits and separators stripped (`frontend01` → `frontend`,
/// `web-02.example.com` → `web`). Keys shorter than 3 characters carry
/// no signal.
pub(crate) fn hostname_key(asset: &Asset) -> Option<String> {
    let host = asset.hostname.as_deref()?.to_lowercase();
    let first_label = host.split('.').next().unwrap_or_default();
    let trimmed =
        first_label.trim_end_matches(|c: char| c.is_ascii_digit() || c == '-' || c == '_');
    if trimmed.len() >= 3 {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// The IPv4 /24 of an asset (`10.0.0.1` → `10.0.0.0/24`). IPv6 addresses
/// carry no subnet signal: the inference model has no IPv6 equivalent of
/// "same subnet" yet.
pub(crate) fn subnet_of(asset: &Asset) -> Option<String> {
    match asset.ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        std::net::IpAddr::V6(_) => None,
    }
}
