//! Shared application state: at most one unlocked `VaultStore` in memory at a time, plus an
//! idle-lock watchdog — the GUI equivalent of the CLI's `vaultkeep shell` session
//! (crates/vault-cli/src/session.rs). A GUI window is inherently a long-lived process, so this
//! auto-lock behavior isn't optional the way it is for one-shot CLI commands — see
//! docs/03-threat-model.md T14.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vault_core::VaultStore;

pub struct Inner {
    pub store: Option<VaultStore>,
    pub last_activity: Instant,
    pub idle_timeout: Duration,
    pub vault_path: PathBuf,
    pub audit_path: PathBuf,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Mutex<Inner>>);

impl AppState {
    pub fn new() -> Self {
        let vault_path = vault_core::default_vault_path();
        let audit_path = vault_core::audit_log_path_for(&vault_path);
        AppState(Arc::new(Mutex::new(Inner {
            store: None,
            last_activity: Instant::now(),
            idle_timeout: Duration::from_secs(300),
            vault_path,
            audit_path,
        })))
    }

    /// Background watchdog: locks (drops the in-memory `VaultStore`, zeroizing key material and
    /// releasing the vault's advisory file lock) after `idle_timeout` of no command activity.
    /// The frontend polls `is_unlocked` and redirects to the unlock screen when this fires.
    pub fn spawn_idle_watchdog(&self) {
        let inner = self.0.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(2));
            let mut guard = match inner.lock() {
                Ok(g) => g,
                Err(_) => return, // poisoned — nothing sensible left to do but stop watching
            };
            if guard.store.is_some() && guard.last_activity.elapsed() > guard.idle_timeout {
                guard.store = None;
            }
        });
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
