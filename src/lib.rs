//! Orbyn — infrastructure discovery, dependency mapping, and migration assessment.
//!
//! Orbyn is organized as a library plus a CLI binary. All interaction happens
//! through the command line; the library surface exists so capabilities can be
//! embedded or reused by other tooling.

pub mod assessment;
pub mod collectors;
pub mod config;
pub mod domain;
pub mod http;
pub mod import;
pub mod integrations;
pub mod metrics;
pub mod output;
pub mod parsing;
pub mod process;
pub mod redact;
pub mod sku;
pub mod store;
