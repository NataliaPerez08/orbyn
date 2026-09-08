//! Small text-parsing helpers shared by collectors and the CLI.
//!
//! Collector output is text from standard tools (`snmpwalk`, `ssh`, PowerShell
//! CSV, `df`). These helpers keep that parsing in one tested place instead of
//! being duplicated per collector.

use std::collections::HashMap;

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
}
