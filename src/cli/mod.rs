//! CLI layer: clap definitions ([`args`]) and command handlers
//! ([`commands`]), plus the terminal- and environment-facing helpers shared
//! across handlers. Application orchestration lives in [`crate::app`].

pub(crate) mod args;
pub(crate) mod commands;

use std::io::BufRead;

use anyhow::{bail, Context, Result};

/// Resolve a secret flag value: the literal `-` reads one trimmed line from
/// stdin so the secret never appears in argv or the environment; any other
/// value passes through unchanged. Values containing newlines or NUL bytes
/// are rejected: they would split the temporary SNMP config file, curl's
/// `-H @-` header stream or curl's `-K -` config stream (config/header
/// injection).
///
/// A literal value warns on stderr: it sits in the process arguments (and
/// shell history) for the whole process lifetime (audit OY-07). Values
/// sourced from `env_var` (clap's env fallback) do not warn.
pub(crate) fn resolve_secret(
    value: Option<String>,
    flag: &str,
    env_var: &str,
) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let secret = if value == "-" {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .with_context(|| format!("reading {flag} from stdin"))?;
        let secret = line.trim();
        if secret.is_empty() {
            bail!("{flag} read an empty secret from stdin");
        }
        secret.to_string()
    } else {
        if secret_needs_argv_warning(&value, env_var) {
            eprintln!(
                "WARNING: {flag} passed as a literal value is visible in the \
                 process arguments (ps, shell history); prefer '-' to read it \
                 from stdin, or set {env_var} (audit OY-07)."
            );
        }
        value
    };
    if secret.contains(['\n', '\r', '\0']) {
        bail!("{flag} cannot contain newlines or NUL bytes");
    }
    Ok(Some(secret))
}

/// True when a secret arrived as a literal flag value (not the stdin marker
/// and not matching the env fallback), leaving it exposed in argv.
fn secret_needs_argv_warning(value: &str, env_var: &str) -> bool {
    value != "-" && std::env::var(env_var).ok().as_deref() != Some(value)
}

/// True when a URL uses plaintext HTTP: an Authorization token would travel
/// unencrypted (audit OY-12).
pub(crate) fn is_plain_http(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("http://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_secret_rejects_control_characters() {
        assert!(resolve_secret(
            Some("bad\nsecret".into()),
            "--community",
            "ORBYN_SNMP_COMMUNITY"
        )
        .is_err());
        assert!(
            resolve_secret(Some("bad\rsecret".into()), "--token", "ORBYN_NETBOX_TOKEN").is_err()
        );
        assert!(
            resolve_secret(Some("bad\0secret".into()), "--token", "ORBYN_NETBOX_TOKEN").is_err()
        );
        assert_eq!(
            resolve_secret(Some("good-secret".into()), "--token", "ORBYN_NETBOX_TOKEN").unwrap(),
            Some("good-secret".to_string())
        );
        assert_eq!(
            resolve_secret(None, "--token", "ORBYN_NETBOX_TOKEN").unwrap(),
            None
        );
    }

    #[test]
    fn literal_secrets_warn_but_env_sourced_do_not() {
        // A throwaway env var keeps this test independent from a developer
        // shell that exports the real secret variables.
        let var = "ORBYN_TEST_SECRET_WARN";
        std::env::remove_var(var);
        assert!(
            secret_needs_argv_warning("literal-value", var),
            "literal flag values are exposed in argv and must warn"
        );
        assert!(
            !secret_needs_argv_warning("-", var),
            "the stdin marker never warns"
        );
        std::env::set_var(var, "from-env");
        assert!(
            !secret_needs_argv_warning("from-env", var),
            "values matching the env fallback do not warn"
        );
        assert!(secret_needs_argv_warning("other", var));
        std::env::remove_var(var);
    }

    #[test]
    fn plain_http_urls_are_detected() {
        assert!(is_plain_http("http://netbox.example.com"));
        assert!(is_plain_http("  HTTP://netbox.example.com  "));
        assert!(!is_plain_http("https://netbox.example.com"));
        assert!(!is_plain_http("https://netbox.example.com/http://x"));
    }
}
