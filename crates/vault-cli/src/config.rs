//! Thin CLI-side wrapper over `vault_core::paths` — kept as its own module so CLI call sites
//! read `config::resolve_vault_path(...)` rather than reaching into `vault_core` directly, but
//! the actual path logic lives in one place (`vault-core`) shared with the GUI. See
//! docs/02-architecture.md §2.7.

use std::path::PathBuf;

pub fn resolve_vault_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit.unwrap_or_else(vault_core::default_vault_path)
}

pub fn audit_log_path_for(vault_path: &std::path::Path) -> PathBuf {
    vault_core::audit_log_path_for(vault_path)
}
