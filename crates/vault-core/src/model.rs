//! Decrypted vault contents. See docs/data-model.md for the authoritative schema reference.

use crate::crypto::KdfParams;
use crate::secret::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub label: String,
    pub value: Secret,
    pub sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalPassword {
    pub value: Secret,
    pub replaced_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub password: Secret,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub totp_seed: Option<Secret>,
    pub custom_fields: Vec<CustomField>,
    pub password_history: Vec<HistoricalPassword>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Non-secret projection of an `Entry`, returned by `list`/`search`. Deliberately has no field
/// capable of carrying `password`/`totp_seed`/sensitive custom-field values — leaking a secret
/// through a listing path is a compile-time impossibility, not just a convention (see
/// docs/03-threat-model.md T10 and docs/cli-reference.md).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub has_totp: bool,
    pub updated_at: DateTime<Utc>,
}

impl From<&Entry> for EntrySummary {
    fn from(e: &Entry) -> Self {
        EntrySummary {
            id: e.id,
            title: e.title.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            tags: e.tags.clone(),
            has_totp: e.totp_seed.is_some(),
            updated_at: e.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorPolicy {
    pub length: u16,
    pub use_upper: bool,
    pub use_lower: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for GeneratorPolicy {
    fn default() -> Self {
        GeneratorPolicy {
            length: 20,
            use_upper: true,
            use_lower: true,
            use_digits: true,
            use_symbols: true,
            avoid_ambiguous: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub kdf_params: KdfParams,
    pub clipboard_clear_seconds: u32,
    pub session_idle_timeout_seconds: u32,
    pub generator_defaults: GeneratorPolicy,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            kdf_params: KdfParams::DEFAULT,
            clipboard_clear_seconds: 20,
            session_idle_timeout_seconds: 300,
            generator_defaults: GeneratorPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub schema_version: u16,
    pub entries: Vec<Entry>,
    pub settings: Settings,
}

impl VaultPayload {
    pub fn new(settings: Settings) -> Self {
        VaultPayload {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
            settings,
        }
    }
}

/// Fields accepted when creating a new entry.
pub struct NewEntry {
    pub title: String,
    pub username: Option<String>,
    pub password: Secret,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub totp_seed: Option<Secret>,
}

/// A sparse patch applied to an existing entry — `None` means "leave unchanged".
#[derive(Default)]
pub struct EntryPatch {
    pub username: Option<Option<String>>,
    pub password: Option<Secret>,
    pub url: Option<Option<String>>,
    pub notes: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub totp_seed: Option<Option<Secret>>,
}
