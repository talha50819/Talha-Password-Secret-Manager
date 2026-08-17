//! OS-appropriate default path resolution.
//!
//! Lives in `vault-core` (not `vault-cli`) so that **every** front end — the CLI and the GUI
//! alike — resolves the exact same default vault location by construction. If this logic were
//! duplicated per front end, a CLI unlock and a GUI unlock could silently disagree about which
//! file "the vault" even is; keeping a single implementation makes that class of bug impossible
//! rather than merely unlikely. See docs/02-architecture.md §2.7.

use directories::BaseDirs;
use std::path::{Path, PathBuf};

/// Default vault path:
/// - Windows: `%APPDATA%\vaultkeep\vault.vkl`
/// - Linux:   `$XDG_DATA_HOME/vaultkeep/vault.vkl` (falls back to `~/.local/share/vaultkeep`)
/// - macOS:   `~/Library/Application Support/vaultkeep/vault.vkl`
///
/// Deliberately built from `BaseDirs::data_dir()` + a single `vaultkeep` segment we append
/// ourselves, rather than `ProjectDirs::from(qualifier, org, app)` — the latter nests an extra
/// `org/app/data` path (e.g. `%APPDATA%\vaultkeep\vaultkeep\data\`) when org and app share a
/// name, which doesn't match the simple path documented in docs/02-architecture.md §2.7 and
/// docs/data-model.md. Caught by visually inspecting the GUI's own vault-path footer during
/// manual testing, not by reading the `directories` crate's source — worth its own note in
/// docs/13-gui.md as a concrete example of why "it compiled and the unit tests passed" isn't
/// the same as "it does what the docs say."
pub fn default_vault_path() -> PathBuf {
    match BaseDirs::new() {
        Some(dirs) => dirs.data_dir().join("vaultkeep").join("vault.vkl"),
        None => {
            // Extremely unlikely (no resolvable home directory); fall back to CWD rather
            // than panicking, since this is only a default that callers can always override.
            PathBuf::from("vault.vkl")
        }
    }
}

/// The audit log lives alongside the vault it describes, named after it, so multiple vaults
/// (e.g. via an explicit `--vault`/custom path) each get their own independent audit trail.
pub fn audit_log_path_for(vault_path: &Path) -> PathBuf {
    let mut path = vault_path.to_path_buf();
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("vault").to_string();
    path.set_file_name(format!("{file_name}.audit.log"));
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_path_is_derived_from_the_vault_file_name() {
        let vault = Path::new("/some/dir/myvault.vkl");
        let audit = audit_log_path_for(vault);
        assert_eq!(audit, Path::new("/some/dir/myvault.vkl.audit.log"));
    }

    #[test]
    fn default_vault_path_ends_with_the_expected_file_name() {
        assert_eq!(default_vault_path().file_name().unwrap(), "vault.vkl");
    }

    #[test]
    fn default_vault_path_has_exactly_one_vaultkeep_segment() {
        // Regression test for the `ProjectDirs`-nesting bug caught during GUI manual testing:
        // the path must not contain the app name twice (e.g. ".../vaultkeep/vaultkeep/...").
        let path = default_vault_path();
        let occurrences = path
            .components()
            .filter(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("vaultkeep"))
            .count();
        assert_eq!(occurrences, 1, "expected exactly one 'vaultkeep' path segment in {path:?}");
    }
}
