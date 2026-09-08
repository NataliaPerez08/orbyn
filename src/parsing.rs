//! Small text-parsing helpers shared by collectors and the CLI.
//!
//! Collector output is text from standard tools (`snmpwalk`, `ssh`, PowerShell
//! CSV, `df`). These helpers keep that parsing in one tested place instead of
//! being duplicated per collector.

use std::collections::HashMap;
use std::net::IpAddr;

/// Split a single CSV line into fields, honoring double-quote escaping.
pub fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

/// Split collector output into `###name`-marked sections.
///
/// A section starts at a line of the form `###os` (short, alphabetic marker)
/// and collects every line until the next marker. Output before the first
/// marker is discarded.
pub fn split_sections(output: &str) -> HashMap<String, Vec<String>> {
    let mut sections: HashMap<String, Vec<String>> = HashMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("###") {
            if !name.is_empty() && name.len() <= 10 && name.chars().all(char::is_alphabetic) {
                sections.entry(name.to_string()).or_default();
                current = Some(name.to_string());
                continue;
            }
        }
        if let Some(name) = &current {
            sections
                .entry(name.clone())
                .or_default()
                .push(line.to_string());
        }
    }
    sections
}

/// Normalize an IP string, collapsing IPv4-mapped IPv6 (`::ffff:10.0.0.5`)
/// to the plain IPv4 form so it compares equal against inventory addresses.
pub fn normalize_ip(raw: &str) -> Option<IpAddr> {
    match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(IpAddr::V4).or(Some(IpAddr::V6(v6))),
        Ok(v4 @ IpAddr::V4(_)) => Some(v4),
        Err(_) => None,
    }
}

/// Parse `IP:port` endpoint strings as emitted by `ss`/`netstat`, including
/// bracketed IPv6 (`[2001:db8::1]:443`).
pub fn parse_addr_port(raw: &str) -> Option<(IpAddr, u16)> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        let (ip, port) = rest.split_once(']')?;
        let port = port.trim_start_matches(':').parse().ok()?;
        return normalize_ip(ip).map(|ip| (ip, port));
    }
    let (ip, port) = raw.rsplit_once(':')?;
    let port = port.parse().ok()?;
    normalize_ip(ip).map(|ip| (ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_csv() {
        let fields = split_csv_line(r#""Microsoft Windows Server 2022","10.0","20348""#);
        assert_eq!(
            fields,
            vec![
                "Microsoft Windows Server 2022".to_string(),
                "10.0".to_string(),
                "20348".to_string()
            ]
        );
    }

    #[test]
    fn keeps_escaped_quotes_and_inner_commas() {
        let fields = split_csv_line(r#""a,""b""",plain"#);
        assert_eq!(fields, vec![r#"a,"b""#.to_string(), "plain".to_string()]);
    }

    #[test]
    fn splits_marker_sections() {
        let out = "noise\n###os\nline1\nline2\n###cpu\ncpu line\n";
        let sections = split_sections(out);
        assert_eq!(sections["os"], vec!["line1", "line2"]);
        assert_eq!(sections["cpu"], vec!["cpu line"]);
    }

    #[test]
    fn crlf_lines_are_trimmed() {
        let sections = split_sections("###os\r\nvalue\r\n");
        assert_eq!(sections["os"], vec!["value"]);
    }

    #[test]
    fn parses_endpoint_forms() {
        assert_eq!(
            parse_addr_port("10.0.0.5:443"),
            Some(("10.0.0.5".parse().unwrap(), 443))
        );
        assert_eq!(
            parse_addr_port("[2001:db8::1]:443"),
            Some(("2001:db8::1".parse().unwrap(), 443))
        );
        assert_eq!(
            parse_addr_port("::ffff:10.0.0.5:5432"),
            Some(("10.0.0.5".parse().unwrap(), 5432)),
            "IPv4-mapped endpoints must collapse to IPv4"
        );
        assert_eq!(parse_addr_port("not-an-endpoint"), None);
    }
}
