//! `vault-core` — security-critical core library for Vaultkeep.
//!
//! This crate deliberately has **no** networking dependency (verified by
//! `.github/workflows/ci.yml`'s dependency-tree check, see docs/05-security-hardening.md) and
//! no direct terminal I/O — it is the reusable, independently-reviewable heart of the vault,
//! consumed today by `vault-cli` and, per the roadmap, by a future GUI.
//!
//! See docs/02-architecture.md for the full architecture and docs/data-model.md for the schema.

pub mod audit;
pub mod crypto;
pub mod error;
pub mod format;
pub mod generator;
pub mod model;
pub mod paths;
pub mod secret;
pub mod store;
pub mod strength;
pub mod totp;

pub use audit::{AuditLog, AuditOp, AuditRecord};
pub use crypto::KdfParams;
pub use error::{Result, VaultError};
pub use model::{CustomField, Entry, EntryPatch, EntrySummary, GeneratorPolicy, HistoricalPassword, NewEntry, Settings};
pub use paths::{audit_log_path_for, default_vault_path};
pub use secret::Secret;
pub use store::VaultStore;
