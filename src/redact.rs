//! Central secret redaction.
//!
//! Orbyn holds credentials in process memory (NetBox token, SNMP community,
//! WinRM password, Prometheus token) and embeds them at the edges into
//! errors or persisted job records. A [`Redactor`] replaces known values
//! with a placeholder so secrets never escape to logs, stderr, or the
//! database.

/// Placeholder used in place of a redacted secret.
pub const REDACTED: &str = "[REDACTED]";

/// Replaces known secret values inside arbitrary strings.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    values: Vec<String>,
}

impl Redactor {
    /// Start with an empty redactor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a secret. Values shorter than 4 chars are ignored to avoid
    /// blanking harmless substrings that just happen to match a very short
    /// token; 4+ chars still cover short default communities such as
    /// `cisco` (audit OY-13: the previous 6-char threshold silently left
    /// them unredacted).
    pub fn add_value(&mut self, value: impl AsRef<str>) {
        let value = value.as_ref();
        if value.len() >= 4 {
            self.values.push(value.to_string());
        }
    }

    /// Register several secrets at once. Empty and short values are skipped.
    pub fn with_values(&mut self, values: impl IntoIterator<Item = impl AsRef<str>>) {
        for value in values {
            self.add_value(value);
        }
    }

    /// Seed from the environment variables Orbyn consults for credentials.
    pub fn from_env() -> Self {
        let mut redactor = Self::new();
        redactor.with_values([
            std::env::var("ORBYN_NETBOX_TOKEN").unwrap_or_default(),
            std::env::var("ORBYN_SNMP_COMMUNITY").unwrap_or_default(),
            std::env::var("ORBYN_WINRM_PASSWORD").unwrap_or_default(),
            std::env::var("ORBYN_PROMETHEUS_TOKEN").unwrap_or_default(),
        ]);
        redactor
    }

    /// Return a copy of `input` with every known secret replaced by
    /// [`REDACTED`]. Strings that carry no registered secret are returned
    /// unchanged.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();
        for value in &self.values {
            if value.is_empty() {
                continue;
            }
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), REDACTED);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_known_values_everywhere() {
        let mut r = Redactor::new();
        r.add_value("supersecrettoken123");
        r.add_value("public");
        assert_eq!(
            r.redact("token=supersecrettoken123 end"),
            "token=[REDACTED] end"
        );
        assert_eq!(
            r.redact("supersecrettoken123 then supersecrettoken123"),
            "[REDACTED] then [REDACTED]"
        );
    }

    #[test]
    fn ignores_short_values() {
        let mut r = Redactor::new();
        r.add_value("abc");
        assert_eq!(r.redact("abcdefghij"), "abcdefghij");
    }

    #[test]
    fn covers_short_default_communities() {
        let mut r = Redactor::new();
        r.add_value("cisco");
        assert_eq!(r.redact("community=cisco"), "community=[REDACTED]");
    }

    #[test]
    fn unchanged_when_no_secret() {
        let r = Redactor::new();
        assert_eq!(r.redact("nothing sensitive"), "nothing sensitive");
    }
}
