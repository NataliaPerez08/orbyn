//! Third-party integrations.
//!
//! NetBox is a source-of-truth importer (read-only); Prometheus is a
//! historical utilization importer (read-only); Ansible and Terraform are
//! automation exporters. All exporters are pure functions over the
//! normalized domain, so they render identically regardless of where the
//! data came from.

pub mod ansible;
pub mod netbox;
pub mod prometheus;
pub mod terraform;
