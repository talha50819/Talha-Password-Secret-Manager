//! OS-appropriate path resolution. See docs/02-architecture.md §2.7.

use directories::ProjectDirs;
use std::path::PathBuf;

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "vaultkeep", "vaultkeep")
}

/// Default vault path:
/// - Windows: `%APPDATA%\vaultkeep\vault.vkl`
/// - Linux:   `$XDG_DATA_HOME/vaultkeep/vault.vkl` (falls back to `~/.local/share/vaultkeep`)
/// - macOS:   `~/Library/Application Support/vaultkeep/vault.vkl`
fn default_vault_path() -> PathBuf {
    match project_dirs() {
        Some(dirs) => dirs.data_dir().join("vault.vkl"),
        None => {
            // Extremely unlikely (no resolvable home directory); fall back to CWD rather
            // than panicking, since this is only a default that `--vault` can always override.
            PathBuf::from("vault.vkl")
        }
    }
}

pub fn resolve_vault_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit.unwrap_or_else(default_vault_path)
}

pub fn audit_log_path_for(vault_path: &std::path::Path) -> PathBuf {
    // The audit log lives alongside the vault it describes, named after it, so multiple
    // vaults (via `--vault`) each get their own independent audit trail.
    let mut path = vault_path.to_path_buf();
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("vault").to_string();
    path.set_file_name(format!("{file_name}.audit.log"));
    path
}
