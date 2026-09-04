//! Persistence layer.
//!
//! Repository traits isolate domain logic from storage so that SQLite can be
//! traded for PostgreSQL (or another store) without touching collectors or
//! assessment logic.

pub mod sqlite;
pub mod traits;

pub use traits::Store;
