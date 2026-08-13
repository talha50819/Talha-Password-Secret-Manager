//! `VaultStore` — the single orchestration point that ties crypto + format + model + audit
//! together. This is the type embedded by the CLI (and, per docs/cli-reference.md, any future
//! GUI). Every mutating method logs to the audit trail internally so a call site cannot forget
//! to (see docs/04-backlog.md US-3.3).

use crate::audit::{AuditLog, AuditOp};
use crate::crypto::{self, KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Result, VaultError};
use crate::format::{self, Header};
use crate::model::{Entry, EntryPatch, EntrySummary, HistoricalPassword, NewEntry, Settings, VaultPayload};
use crate::secret::Secret;
use chrono::Utc;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct VaultStore {
    path: PathBuf,
    lock_path: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    header: Header,
    payload: VaultPayload,
    audit: AuditLog,
}

impl Drop for VaultStore {
    fn drop(&mut self) {
        // Releases the advisory cross-process lock (VAPT finding V-11, docs/08-vapt-report.md)
        // on every path out of scope — normal completion, `?`-propagated errors, and explicit
        // `lock()` alike — since all of those run destructors normally (only a hard process
        // kill or a panic under `panic = "abort"` skips this, which is why a stale lock is a
        // documented, manually-recoverable limitation rather than treated as impossible).
        format::release_lock(&self.lock_path);
    }
}

fn read_keyfile(path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    match path {
        Some(p) => Ok(Some(std::fs::read(p)?)),
        None => Ok(None),
    }
}

impl VaultStore {
    /// Create a brand-new vault. Fails if a vault already exists at `path`.
    pub fn create(
        path: &Path,
        master_password: &Secret,
        keyfile: Option<&Path>,
        kdf_params: KdfParams,
        audit_log_path: &Path,
    ) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        crate::strength::validate_master_password(master_password.expose())?;

        let keyfile_bytes = read_keyfile(keyfile)?;
        let salt = crypto::random_salt();
        let nonce = crypto::random_nonce();
        let key = crypto::derive_key(master_password.expose().as_bytes(), &salt, &kdf_params, keyfile_bytes.as_deref())?;

        let header = Header::new(salt, kdf_params, keyfile.is_some(), nonce);
        let payload = VaultPayload::new(Settings { kdf_params, ..Settings::default() });

        // Acquired as the last fallible step before `store` takes ownership of it: every prior
        // fallible call happens before any lock exists (nothing to leak), and every fallible
        // call after this point runs against an already-constructed `store`, whose `Drop`
        // releases the lock automatically even on early return via `?`.
        let lock_path = format::acquire_lock(path)?;
        let mut store = VaultStore {
            path: path.to_path_buf(),
            lock_path,
            key,
            header,
            payload,
            audit: AuditLog::new(audit_log_path.to_path_buf()),
        };
        store.save()?;
        store.audit.log(AuditOp::Init, None)?;
        Ok(store)
    }

    /// Open an existing vault. Any authentication or format failure returns a single generic
    /// `AuthenticationFailed`/`CorruptVault`/`UnsupportedVersion` error — see error.rs.
    pub fn open(path: &Path, master_password: &Secret, keyfile: Option<&Path>, audit_log_path: &Path) -> Result<Self> {
        let (header, ciphertext) = format::read_vault(path)?;
        if header.keyfile_bound && keyfile.is_none() {
            return Err(VaultError::KeyfileRequired);
        }
        let keyfile_bytes = read_keyfile(keyfile)?;

        let key = crypto::derive_key(
            master_password.expose().as_bytes(),
            &header.kdf_salt,
            &header.kdf_params,
            keyfile_bytes.as_deref(),
        )?;

        let aad = header.to_bytes();
        let audit = AuditLog::new(audit_log_path.to_path_buf());
        let plaintext = match crypto::decrypt(&key, &header.nonce, &ciphertext, &aad) {
            Ok(pt) => pt,
            Err(e) => {
                let _ = audit.log(AuditOp::UnlockFailed, None);
                return Err(e);
            }
        };

        let payload: VaultPayload = postcard::from_bytes(&plaintext).map_err(|_| VaultError::CorruptVault)?;
        audit.log(AuditOp::UnlockSuccess, None)?;

        // Acquired last, immediately before construction — see the comment in `create()` for
        // why this ordering is what makes the lock leak-free on every error path.
        let lock_path = format::acquire_lock(path)?;
        Ok(VaultStore { path: path.to_path_buf(), lock_path, key, header, payload, audit })
    }

    /// Re-encrypt and atomically persist the current in-memory state under a fresh random
    /// nonce (nonces are never reused across writes for a given key).
    pub fn save(&mut self) -> Result<()> {
        let plaintext = postcard::to_allocvec(&self.payload).map_err(|_| VaultError::Serialization)?;
        self.header.nonce = crypto::random_nonce();
        let aad = self.header.to_bytes();
        let ciphertext = crypto::encrypt(&self.key, &self.header.nonce, &plaintext, &aad)?;
        format::write_vault_atomic(&self.path, &self.header, &ciphertext)?;
        Ok(())
    }

    /// Change the master password (and/or KDF profile): derive a fresh salt + key, re-encrypt,
    /// and persist. Entries are untouched — only the outer envelope changes.
    pub fn rekey(&mut self, new_password: &Secret, new_kdf_params: Option<KdfParams>, keyfile: Option<&Path>) -> Result<()> {
        crate::strength::validate_master_password(new_password.expose())?;
        let keyfile_bytes = read_keyfile(keyfile)?;
        let params = new_kdf_params.unwrap_or(self.header.kdf_params);
        let salt = crypto::random_salt();
        let new_key = crypto::derive_key(new_password.expose().as_bytes(), &salt, &params, keyfile_bytes.as_deref())?;

        self.key = new_key;
        self.header.kdf_salt = salt;
        self.header.kdf_params = params;
        self.header.keyfile_bound = keyfile.is_some();
        self.payload.settings.kdf_params = params;
        self.save()?;
        self.audit.log(AuditOp::PasswordChanged, None)?;
        Ok(())
    }

    pub fn add_entry(&mut self, new_entry: NewEntry) -> Result<Uuid> {
        if new_entry.title.trim().is_empty() {
            return Err(VaultError::InvalidInput("title must not be empty".into()));
        }
        if self.payload.entries.iter().any(|e| e.title == new_entry.title) {
            return Err(VaultError::DuplicateTitle(new_entry.title));
        }
        let now = Utc::now();
        let id = Uuid::new_v4();
        self.payload.entries.push(Entry {
            id,
            title: new_entry.title,
            username: new_entry.username,
            password: new_entry.password,
            url: new_entry.url,
            notes: new_entry.notes,
            tags: new_entry.tags,
            totp_seed: new_entry.totp_seed,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
        });
        self.save()?;
        self.audit.log(AuditOp::Add, Some(id))?;
        Ok(id)
    }

    fn find_index(&self, id_or_title: &str) -> Result<usize> {
        if let Ok(uuid) = Uuid::parse_str(id_or_title) {
            if let Some(idx) = self.payload.entries.iter().position(|e| e.id == uuid) {
                return Ok(idx);
            }
        }
        self.payload
            .entries
            .iter()
            .position(|e| e.title.eq_ignore_ascii_case(id_or_title))
            .ok_or_else(|| VaultError::EntryNotFound(id_or_title.to_string()))
    }

    pub fn get_entry(&self, id_or_title: &str) -> Result<&Entry> {
        let idx = self.find_index(id_or_title)?;
        Ok(&self.payload.entries[idx])
    }

    /// Convenience for the CLI: fetch + audit-log a GET in one call.
    pub fn get_entry_audited(&self, id_or_title: &str) -> Result<&Entry> {
        let idx = self.find_index(id_or_title)?;
        self.audit.log(AuditOp::Get, Some(self.payload.entries[idx].id))?;
        Ok(&self.payload.entries[idx])
    }

    pub fn edit_entry(&mut self, id_or_title: &str, patch: EntryPatch) -> Result<()> {
        let idx = self.find_index(id_or_title)?;
        let entry = &mut self.payload.entries[idx];

        if let Some(new_password) = patch.password {
            entry.password_history.push(HistoricalPassword {
                value: std::mem::replace(&mut entry.password, new_password),
                replaced_at: Utc::now(),
            });
        }
        if let Some(username) = patch.username {
            entry.username = username;
        }
        if let Some(url) = patch.url {
            entry.url = url;
        }
        if let Some(notes) = patch.notes {
            entry.notes = notes;
        }
        if let Some(tags) = patch.tags {
            entry.tags = tags;
        }
        if let Some(totp_seed) = patch.totp_seed {
            entry.totp_seed = totp_seed;
        }
        entry.updated_at = Utc::now();
        let id = entry.id;

        self.save()?;
        self.audit.log(AuditOp::Edit, Some(id))?;
        Ok(())
    }

    pub fn remove_entry(&mut self, id_or_title: &str) -> Result<()> {
        let idx = self.find_index(id_or_title)?;
        let id = self.payload.entries[idx].id;
        self.payload.entries.remove(idx);
        self.save()?;
        self.audit.log(AuditOp::Delete, Some(id))?;
        Ok(())
    }

    pub fn list(&self, tag: Option<&str>) -> Vec<EntrySummary> {
        self.payload
            .entries
            .iter()
            .filter(|e| tag.map(|t| e.tags.iter().any(|et| et.eq_ignore_ascii_case(t))).unwrap_or(true))
            .map(EntrySummary::from)
            .collect()
    }

    pub fn search(&self, query: &str) -> Vec<EntrySummary> {
        let q = query.to_ascii_lowercase();
        self.payload
            .entries
            .iter()
            .filter(|e| {
                e.title.to_ascii_lowercase().contains(&q)
                    || e.username.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    || e.url.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    || e.notes.as_deref().unwrap_or("").to_ascii_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_ascii_lowercase().contains(&q))
            })
            .map(EntrySummary::from)
            .collect()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.payload.entries
    }

    pub fn settings(&self) -> &Settings {
        &self.payload.settings
    }

    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.payload.settings
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicit lock: drop the derived key immediately rather than waiting for `Drop`.
    /// Consumes `self`; the caller can no longer use the store afterward.
    pub fn lock(self) {
        let _ = self.audit.log(AuditOp::Lock, None);
        // `self.key` (Zeroizing) and `self.payload` are dropped here.
    }

    pub const fn key_len() -> usize {
        KEY_LEN
    }
    pub const fn salt_len() -> usize {
        SALT_LEN
    }
    pub const fn nonce_len() -> usize {
        NONCE_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use tempfile::tempdir;

    fn store_paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault.vkl");
        let audit = dir.path().join("audit.log");
        (dir, vault, audit)
    }

    #[test]
    fn create_then_open_round_trips() {
        let (_dir, vault_path, audit_path) = store_paths();
        let pw = Secret::new("correct horse battery staple");
        {
            let mut store =
                VaultStore::create(&vault_path, &pw, None, KdfParams::INTERACTIVE, &audit_path).unwrap();
            store
                .add_entry(NewEntry {
                    title: "github.com".into(),
                    username: Some("alice".into()),
                    password: Secret::new("s3cr3t!"),
                    url: Some("https://github.com".into()),
                    notes: None,
                    tags: vec!["dev".into()],
                    totp_seed: None,
                })
                .unwrap();
        }

        let store = VaultStore::open(&vault_path, &pw, None, &audit_path).unwrap();
        let entry = store.get_entry("github.com").unwrap();
        assert_eq!(entry.password, Secret::new("s3cr3t!"));
        assert_eq!(entry.username.as_deref(), Some("alice"));
    }

    #[test]
    fn wrong_password_fails_closed() {
        let (_dir, vault_path, audit_path) = store_paths();
        VaultStore::create(&vault_path, &Secret::new("right-password"), None, KdfParams::INTERACTIVE, &audit_path)
            .unwrap();
        let result = VaultStore::open(&vault_path, &Secret::new("wrong-password"), None, &audit_path);
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn create_refuses_to_overwrite_existing_vault() {
        let (_dir, vault_path, audit_path) = store_paths();
        let pw = Secret::new("password-one");
        VaultStore::create(&vault_path, &pw, None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let result = VaultStore::create(&vault_path, &pw, None, KdfParams::INTERACTIVE, &audit_path);
        assert!(matches!(result, Err(VaultError::AlreadyExists)));
    }

    #[test]
    fn keyfile_is_required_when_vault_was_bound_to_one() {
        let (dir, vault_path, audit_path) = store_paths();
        let keyfile_path = dir.path().join("key.bin");
        std::fs::write(&keyfile_path, b"random-keyfile-bytes").unwrap();
        let pw = Secret::new("keyfile-master-pw1");
        VaultStore::create(&vault_path, &pw, Some(&keyfile_path), KdfParams::INTERACTIVE, &audit_path).unwrap();

        let without_keyfile = VaultStore::open(&vault_path, &pw, None, &audit_path);
        assert!(matches!(without_keyfile, Err(VaultError::KeyfileRequired)));

        let with_keyfile = VaultStore::open(&vault_path, &pw, Some(&keyfile_path), &audit_path);
        assert!(with_keyfile.is_ok());
    }

    #[test]
    fn duplicate_title_is_rejected() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store = VaultStore::create(&vault_path, &Secret::new("test-master-pw1"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let new_entry = || NewEntry {
            title: "dup".into(),
            username: None,
            password: Secret::new("x"),
            url: None,
            notes: None,
            tags: vec![],
            totp_seed: None,
        };
        store.add_entry(new_entry()).unwrap();
        assert!(matches!(store.add_entry(new_entry()), Err(VaultError::DuplicateTitle(_))));
    }

    #[test]
    fn edit_pushes_old_password_to_history() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store = VaultStore::create(&vault_path, &Secret::new("test-master-pw1"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let id = store
            .add_entry(NewEntry {
                title: "site".into(),
                username: None,
                password: Secret::new("old-pass"),
                url: None,
                notes: None,
                tags: vec![],
                totp_seed: None,
            })
            .unwrap();
        store
            .edit_entry(&id.to_string(), EntryPatch { password: Some(Secret::new("new-pass")), ..Default::default() })
            .unwrap();
        let entry = store.get_entry(&id.to_string()).unwrap();
        assert_eq!(entry.password, Secret::new("new-pass"));
        assert_eq!(entry.password_history.len(), 1);
        assert_eq!(entry.password_history[0].value, Secret::new("old-pass"));
    }

    #[test]
    fn remove_deletes_the_entry() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store = VaultStore::create(&vault_path, &Secret::new("test-master-pw1"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let id = store
            .add_entry(NewEntry { title: "x".into(), username: None, password: Secret::new("p"), url: None, notes: None, tags: vec![], totp_seed: None })
            .unwrap();
        store.remove_entry(&id.to_string()).unwrap();
        assert!(matches!(store.get_entry(&id.to_string()), Err(VaultError::EntryNotFound(_))));
    }

    #[test]
    fn list_and_search_never_expose_passwords() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store = VaultStore::create(&vault_path, &Secret::new("test-master-pw1"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        store
            .add_entry(NewEntry { title: "bank".into(), username: Some("bob".into()), password: Secret::new("super-secret-value"), url: None, notes: None, tags: vec![], totp_seed: None })
            .unwrap();
        let listed = store.list(None);
        let json = serde_json::to_string(&listed).unwrap();
        assert!(!json.contains("super-secret-value"));

        let found = store.search("bank");
        let json2 = serde_json::to_string(&found).unwrap();
        assert!(!json2.contains("super-secret-value"));
    }

    #[test]
    fn rekey_preserves_entries_and_changes_the_password() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store = VaultStore::create(&vault_path, &Secret::new("old-master"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        store
            .add_entry(NewEntry { title: "x".into(), username: None, password: Secret::new("p"), url: None, notes: None, tags: vec![], totp_seed: None })
            .unwrap();
        store.rekey(&Secret::new("new-master"), None, None).unwrap();
        drop(store);

        assert!(matches!(
            VaultStore::open(&vault_path, &Secret::new("old-master"), None, &audit_path),
            Err(VaultError::AuthenticationFailed)
        ));
        let reopened = VaultStore::open(&vault_path, &Secret::new("new-master"), None, &audit_path).unwrap();
        assert!(reopened.get_entry("x").is_ok());
    }

    #[test]
    fn tampered_vault_file_refuses_to_open() {
        let (_dir, vault_path, audit_path) = store_paths();
        let pw = Secret::new("test-master-pw1");
        VaultStore::create(&vault_path, &pw, None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let mut bytes = std::fs::read(&vault_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&vault_path, bytes).unwrap();
        assert!(matches!(VaultStore::open(&vault_path, &pw, None, &audit_path), Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn create_rejects_a_master_password_below_the_nist_minimum_length() {
        let (_dir, vault_path, audit_path) = store_paths();
        let result = VaultStore::create(&vault_path, &Secret::new("short1"), None, KdfParams::INTERACTIVE, &audit_path);
        assert!(matches!(result, Err(VaultError::InvalidInput(_))));
        assert!(!vault_path.exists());
    }

    #[test]
    fn create_rejects_a_common_master_password_even_if_long_enough() {
        let (_dir, vault_path, audit_path) = store_paths();
        let result = VaultStore::create(&vault_path, &Secret::new("password1"), None, KdfParams::INTERACTIVE, &audit_path);
        assert!(matches!(result, Err(VaultError::InvalidInput(_))));
    }

    #[test]
    fn rekey_rejects_a_weak_new_master_password() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store =
            VaultStore::create(&vault_path, &Secret::new("test-master-pw1"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let result = store.rekey(&Secret::new("weak"), None, None);
        assert!(matches!(result, Err(VaultError::InvalidInput(_))));
        // the vault must still be openable with the original password — rekey did not partially apply
        drop(store);
        assert!(VaultStore::open(&vault_path, &Secret::new("test-master-pw1"), None, &audit_path).is_ok());
    }

    #[test]
    fn opening_the_same_vault_twice_concurrently_is_rejected() {
        let (_dir, vault_path, audit_path) = store_paths();
        let pw = Secret::new("test-master-pw1");
        let first = VaultStore::create(&vault_path, &pw, None, KdfParams::INTERACTIVE, &audit_path).unwrap();

        let second = VaultStore::open(&vault_path, &pw, None, &audit_path);
        assert!(matches!(second, Err(VaultError::Locked(_))));

        drop(first); // releases the lock
        assert!(VaultStore::open(&vault_path, &pw, None, &audit_path).is_ok());
    }

    #[test]
    fn dropping_a_store_releases_its_lock_file() {
        let (_dir, vault_path, audit_path) = store_paths();
        let pw = Secret::new("test-master-pw1");
        let store = VaultStore::create(&vault_path, &pw, None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        let lock_path = format::lock_path_for(&vault_path);
        assert!(lock_path.exists());
        drop(store);
        assert!(!lock_path.exists());
    }

    #[test]
    fn audit_log_never_contains_secret_values_or_titles() {
        let (_dir, vault_path, audit_path) = store_paths();
        let mut store = VaultStore::create(&vault_path, &Secret::new("test-master-pw1"), None, KdfParams::INTERACTIVE, &audit_path).unwrap();
        store
            .add_entry(NewEntry {
                title: "very-sensitive-bank-title".into(),
                username: Some("username-value".into()),
                password: Secret::new("plaintext-password-value"),
                url: None,
                notes: None,
                tags: vec![],
                totp_seed: None,
            })
            .unwrap();
        let log_contents = std::fs::read_to_string(&audit_path).unwrap();
        assert!(!log_contents.contains("very-sensitive-bank-title"));
        assert!(!log_contents.contains("username-value"));
        assert!(!log_contents.contains("plaintext-password-value"));
    }
}
