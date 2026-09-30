//! Shared HTTP call plumbing for the external APIs (NetBox, Prometheus,
//! Zabbix, WinRM).
//!
//! Every call already runs through the `curl` binary under a timeout and a
//! response cap ([`crate::process::run_captured`]). This module adds the two
//! pieces the API clients share on top of that:
//!
//! 1. Reading the HTTP status curl appends to stdout (`-w %{http_code}`), so
//!    a 401, a 429 or a 503 is distinguishable from a good response without
//!    `-f`, which would discard the error body an operator needs.
//! 2. A small retry policy ([`RetryPolicy`]) that replays only the failures a
//!    later attempt could plausibly fix: timeouts, dropped connections, rate
//!    limits and 5xx replies. Everything else (bad credentials, a rejected
//!    request, a response Orbyn cannot use) fails on the first attempt, so a
//!    misconfiguration does not turn into a retry storm.

use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, Result};

/// Attempts per call, including the first: one call plus two replays. The
/// APIs Orbyn talks to are read-only queries, so a replay is cheap, while an
/// unbounded loop against a struggling endpoint only extends the outage.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// First backoff pause; it doubles per replay up to [`DEFAULT_MAX_DELAY`].
pub const DEFAULT_BASE_DELAY: Duration = Duration::from_millis(500);

/// Backoff ceiling. With the defaults the total pause across all replays is
/// bounded at 1.5 s, so a slow endpoint fails visibly rather than stalling a
/// long import.
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(2);

/// How often, and how patiently, a call is replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts per call; 1 disables retries.
    pub max_attempts: u32,
    /// Pause before the first replay.
    pub base_delay: Duration,
    /// Ceiling for the doubling backoff.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_delay: DEFAULT_BASE_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
        }
    }
}

impl RetryPolicy {
    /// A policy that never waits: the unit tests exercise the retry loop
    /// without paying for the backoff.
    #[cfg(test)]
    pub fn immediate() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// The pause after `attempt` (1-based) failed: `base_delay`, doubled per
    /// attempt, capped at `max_delay`.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(16);
        self.base_delay
            .saturating_mul(1u32 << shift)
            .min(self.max_delay)
    }
}

/// One external API attempt: either a value, or a failure classified by
/// whether replaying it could help.
pub type Attempt<T> = Result<T, CallFailure>;

/// A failed API attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFailure {
    /// A timeout, a dropped connection, a rate limit or a 5xx reply: the
    /// same request may well succeed a moment later.
    Transient(String),
    /// Rejected credentials, a bad request, or a response Orbyn cannot use:
    /// replaying it would fail identically.
    Permanent(String),
}

impl CallFailure {
    /// A failure that [`with_retries`] may replay.
    pub fn transient(message: impl Into<String>) -> Self {
        Self::Transient(message.into())
    }

    /// A failure that fails the call immediately.
    pub fn permanent(message: impl Into<String>) -> Self {
        Self::Permanent(message.into())
    }

    /// Whether a later attempt could succeed.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }

    /// The operator-facing description of the failure.
    pub fn message(&self) -> &str {
        match self {
            Self::Transient(message) | Self::Permanent(message) => message,
        }
    }
}

impl From<anyhow::Error> for CallFailure {
    /// Orbyn's own failures (an unusable URL, a missing `curl`, an oversized
    /// response) are permanent unless a client explicitly classified them:
    /// only [`CallFailure::transient`] marks a call replayable.
    fn from(e: anyhow::Error) -> Self {
        Self::Permanent(format!("{e:#}"))
    }
}

impl std::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for CallFailure {}

/// Run `op` until it succeeds, fails permanently, or exhausts `policy`.
///
/// `what` describes the call in error messages. Each attempt is numbered from
/// 1 and passed to `op`, so a client can label its own diagnostics. An
/// exhausted call reports how many attempts it made.
pub async fn with_retries<T, F, Fut>(policy: &RetryPolicy, what: &str, mut op: F) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Attempt<T>>,
{
    let mut attempt = 1u32;
    loop {
        let failure = match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(failure) => failure,
        };
        if !failure.is_transient() || attempt >= policy.max_attempts.max(1) {
            return Err(if attempt > 1 {
                anyhow!("{what} failed after {attempt} attempts: {failure}")
            } else {
                anyhow!("{what} failed: {failure}")
            });
        }
        let pause = policy.backoff(attempt);
        tracing::warn!(
            attempt,
            max_attempts = policy.max_attempts,
            delay_ms = pause.as_millis() as u64,
            error = failure.message(),
            "retrying external API call"
        );
        tokio::time::sleep(pause).await;
        attempt += 1;
    }
}

/// Split curl stdout into `(body, status)` using the 3-digit `-w` trailer.
pub fn split_http_status(out: &str) -> Option<(&str, u16)> {
    if out.len() < 3 {
        return None;
    }
    let (body, status) = out.split_at(out.len() - 3);
    if !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    status.parse().ok().map(|status| (body, status))
}

/// Whether an HTTP status describes a condition a later attempt may resolve:
/// request timeout, too many requests, and the server-side failures a read API
/// produces under load. Every other status (including 501/505, which will
/// never start working) is permanent.
pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Whether a curl exit code describes a transport problem worth replaying:
/// connection refused (`7`), a truncated transfer (`18`), a timeout (`28`),
/// a TLS handshake failure (`35`), an empty reply (`52`) and a broken send or
/// receive (`55`, `56`). Argument, TLS verification and protocol errors are
/// permanent: the same command line would fail again.
pub fn is_retryable_curl_exit(code: i32) -> bool {
    matches!(code, 7 | 18 | 28 | 35 | 52 | 55 | 56)
}

/// A one-line excerpt of an unexpected response body for error messages.
pub fn excerpt(body: &str) -> String {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > 200 {
        format!("{}...", collapsed.chars().take(200).collect::<String>())
    } else {
        collapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn split_http_status_separates_body_and_trailer() {
        assert_eq!(split_http_status("body200"), Some(("body", 200)));
        assert_eq!(split_http_status("200"), Some(("", 200)));
        assert_eq!(split_http_status(""), None);
        assert_eq!(split_http_status("20"), None);
        assert_eq!(split_http_status("body2x0"), None);
    }

    #[test]
    fn only_transient_statuses_are_retryable() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(is_retryable_status(status), "HTTP {status}");
        }
        for status in [200, 201, 301, 400, 401, 403, 404, 405, 409, 501, 505] {
            assert!(!is_retryable_status(status), "HTTP {status}");
        }
    }

    #[test]
    fn only_transport_curl_exits_are_retryable() {
        for code in [7, 18, 28, 35, 52, 55, 56] {
            assert!(is_retryable_curl_exit(code), "curl exit {code}");
        }
        for code in [1, 2, 3, 5, 6, 22, 23, 47, 60, 77, 127] {
            assert!(
                !is_retryable_curl_exit(code),
                "curl exit {code} must not be replayed"
            );
        }
    }

    #[test]
    fn backoff_doubles_and_saturates_at_the_ceiling() {
        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(250),
        };
        assert_eq!(policy.backoff(1), Duration::from_millis(100));
        assert_eq!(policy.backoff(2), Duration::from_millis(200));
        assert_eq!(policy.backoff(3), Duration::from_millis(250));
        assert_eq!(policy.backoff(9), Duration::from_millis(250));
    }

    #[tokio::test]
    async fn a_transient_failure_is_replayed_until_it_succeeds() {
        let policy = RetryPolicy::immediate();
        let calls = Arc::new(AtomicU32::new(0));
        let seen = calls.clone();

        let value = with_retries(&policy, "the API call", move |attempt| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::Relaxed);
                if attempt < 3 {
                    Err(CallFailure::transient("HTTP 503"))
                } else {
                    Ok("inventory")
                }
            }
        })
        .await
        .expect("third attempt succeeds");

        assert_eq!(value, "inventory");
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn a_permanent_failure_is_not_replayed() {
        let policy = RetryPolicy::immediate();
        let calls = Arc::new(AtomicU32::new(0));
        let seen = calls.clone();

        let error = with_retries(&policy, "the NetBox request to /api", move |_| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::Relaxed);
                Err::<(), _>(CallFailure::permanent("HTTP 401"))
            }
        })
        .await
        .expect_err("permanent failures propagate");

        assert_eq!(calls.load(Ordering::Relaxed), 1, "one attempt only");
        assert_eq!(
            error.to_string(),
            "the NetBox request to /api failed: HTTP 401"
        );
    }

    #[tokio::test]
    async fn an_exhausted_policy_reports_the_attempt_count() {
        let policy = RetryPolicy::immediate();
        let calls = Arc::new(AtomicU32::new(0));
        let seen = calls.clone();

        let error = with_retries(&policy, "the Prometheus query", move |_| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::Relaxed);
                Err::<(), _>(CallFailure::transient("curl exited with 28"))
            }
        })
        .await
        .expect_err("retries are bounded");

        assert_eq!(
            calls.load(Ordering::Relaxed),
            DEFAULT_MAX_ATTEMPTS,
            "attempts stay bounded"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "the Prometheus query failed after {DEFAULT_MAX_ATTEMPTS} attempts: \
                 curl exited with 28"
            )
        );
    }

    #[tokio::test]
    async fn a_single_attempt_policy_never_replays() {
        let policy = RetryPolicy {
            max_attempts: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let calls = Arc::new(AtomicU32::new(0));
        let seen = calls.clone();

        let error = with_retries(&policy, "the Zabbix call", move |_| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::Relaxed);
                Err::<(), _>(CallFailure::transient("HTTP 429"))
            }
        })
        .await
        .expect_err("a single attempt cannot be replayed");

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(error.to_string(), "the Zabbix call failed: HTTP 429");
    }

    #[test]
    fn orbyn_failures_default_to_permanent() {
        let failure = CallFailure::from(anyhow!("invalid URL 'htp://x'"));
        assert!(!failure.is_transient());
        assert_eq!(failure.message(), "invalid URL 'htp://x'");
    }

    #[test]
    fn excerpt_collapses_and_truncates() {
        assert_eq!(excerpt("  a\n\tb  c "), "a b c");
        let long = "x".repeat(300);
        assert_eq!(excerpt(&long).len(), 203);
        // Truncation must not split a multi-byte character.
        let wide = "é".repeat(300);
        assert!(excerpt(&wide).ends_with("..."));
        assert!(excerpt(&wide).chars().count() <= 203);
    }
}
