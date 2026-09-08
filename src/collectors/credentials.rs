//! Credential profiles for host-level collectors (v0.3).
//!
//! Orbyn deliberately **does not store credentials**. A credential profile
//! describes *how* to authenticate — an ssh-agent, or a reference to an
//! identity file on disk — and never carries secret material itself:
//!
//! - `username`: login user (empty means the transport default, i.e. the
//!   current user for `ssh`);
//! - `identity_file`: path to a private key; the key itself is never read,
//!   copied or logged by Orbyn;
//! - `port`: remote port.
//!
//! Password authentication is intentionally unsupported: passing passwords
//! through subprocess arguments or storing them would violate the security
//! rules in SECURITY.md. Operators who need password-based auth should front
//! it with an agent (e.g. `ssh-agent`) or use key files.

use std::path::PathBuf;

/// How Orbyn authenticates against a remote host.
#[derive(Debug, Clone)]
pub struct CredentialProfile {
    /// Login user; empty means the transport default (current user for ssh).
    pub username: String,
    /// Remote port (22 for ssh unless configured otherwise).
    pub port: u16,
    /// Optional path to an identity (private key) file. Never a secret value.
    pub identity_file: Option<PathBuf>,
}

impl CredentialProfile {
    pub fn new(username: impl Into<String>, port: u16, identity_file: Option<PathBuf>) -> Self {
        Self {
            username: username.into(),
            port,
            identity_file,
        }
    }
}

impl Default for CredentialProfile {
    fn default() -> Self {
        Self {
            username: String::new(),
            port: 22,
            identity_file: None,
        }
    }
}
