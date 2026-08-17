//! Tauri commands: the entire surface the frontend can call. Mirrors the CLI's command set
//! (docs/cli-reference.md) so the two front ends stay behaviorally consistent, both built on
//! the same unmodified `vault-core`.

use crate::state::AppState;
use chrono::Utc;
use tauri::State;
use vault_core::crypto::KdfParams;
use vault_core::model::{EntryPatch, GeneratorPolicy, NewEntry};
use vault_core::secret::Secret;
use vault_core::{generator, strength, totp, VaultStore};

type CmdResult<T> = Result<T, String>;

// ---------------------------------------------------------------------------------------------
// DTOs — deliberately explicit conversions, never `#[derive(Serialize)]` on `vault_core::Entry`
// directly for anything but `get_entry`, so a secret can only reach the frontend where a call
// site visibly, deliberately calls `.expose()`. See crates/vault-core/src/secret.rs.
// ---------------------------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct EntrySummaryDto {
    id: String,
    title: String,
    username: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
    has_totp: bool,
    updated_at: String,
}

impl From<vault_core::EntrySummary> for EntrySummaryDto {
    fn from(e: vault_core::EntrySummary) -> Self {
        EntrySummaryDto {
            id: e.id.to_string(),
            title: e.title,
            username: e.username,
            url: e.url,
            tags: e.tags,
            has_totp: e.has_totp,
            updated_at: e.updated_at.to_rfc3339(),
        }
    }
}

#[derive(serde::Serialize)]
pub struct EntryDetailDto {
    id: String,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    totp_seed: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(serde::Serialize)]
pub struct StrengthDto {
    id: String,
    title: String,
    level: String,
    estimated_bits: f64,
    is_common_password: bool,
    reused_in: Vec<String>,
    age_days: Option<i64>,
    stale: bool,
}

#[derive(serde::Serialize)]
pub struct AuditRecordDto {
    ts: String,
    op: String,
    entry_id: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn with_store<T>(state: &State<AppState>, f: impl FnOnce(&VaultStore) -> CmdResult<T>) -> CmdResult<T> {
    let mut guard = state.0.lock().map_err(|_| "internal error: lock poisoned".to_string())?;
    guard.last_activity = std::time::Instant::now();
    match &guard.store {
        Some(store) => f(store),
        None => Err("vault is locked".to_string()),
    }
}

fn with_store_mut<T>(state: &State<AppState>, f: impl FnOnce(&mut VaultStore) -> CmdResult<T>) -> CmdResult<T> {
    let mut guard = state.0.lock().map_err(|_| "internal error: lock poisoned".to_string())?;
    guard.last_activity = std::time::Instant::now();
    match &mut guard.store {
        Some(store) => f(store),
        None => Err("vault is locked".to_string()),
    }
}

fn none_if_blank(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.trim().is_empty())
}

// ---------------------------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------------------------

#[tauri::command]
pub fn vault_exists(state: State<AppState>) -> bool {
    let guard = state.0.lock().unwrap();
    guard.vault_path.exists()
}

#[tauri::command]
pub fn vault_path_display(state: State<AppState>) -> String {
    let guard = state.0.lock().unwrap();
    guard.vault_path.display().to_string()
}

#[tauri::command]
pub fn is_unlocked(state: State<AppState>) -> bool {
    let guard = state.0.lock().unwrap();
    guard.store.is_some()
}

#[tauri::command]
pub fn create_vault(state: State<AppState>, password: String, confirm: String) -> CmdResult<()> {
    if password != confirm {
        return Err("passwords did not match".into());
    }
    let mut guard = state.0.lock().map_err(|_| "internal error: lock poisoned".to_string())?;
    let store = VaultStore::create(&guard.vault_path, &Secret::new(password), None, KdfParams::DEFAULT, &guard.audit_path)
        .map_err(|e| e.to_string())?;
    guard.store = Some(store);
    guard.last_activity = std::time::Instant::now();
    Ok(())
}

#[tauri::command]
pub fn unlock_vault(state: State<AppState>, password: String) -> CmdResult<()> {
    let mut guard = state.0.lock().map_err(|_| "internal error: lock poisoned".to_string())?;
    let store =
        VaultStore::open(&guard.vault_path, &Secret::new(password), None, &guard.audit_path).map_err(|e| e.to_string())?;
    guard.store = Some(store);
    guard.last_activity = std::time::Instant::now();
    Ok(())
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> CmdResult<()> {
    let mut guard = state.0.lock().map_err(|_| "internal error: lock poisoned".to_string())?;
    guard.store = None; // Drop zeroizes the key and releases the advisory file lock
    Ok(())
}

#[tauri::command]
pub fn change_master_password(state: State<AppState>, new_password: String, confirm: String) -> CmdResult<()> {
    if new_password != confirm {
        return Err("passwords did not match".into());
    }
    with_store_mut(&state, |store| {
        store.rekey(&Secret::new(new_password), None, None).map_err(|e| e.to_string())
    })
}

// ---------------------------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------------------------

#[tauri::command]
pub fn list_entries(state: State<AppState>, tag: Option<String>) -> CmdResult<Vec<EntrySummaryDto>> {
    with_store(&state, |store| Ok(store.list(tag.as_deref()).into_iter().map(EntrySummaryDto::from).collect()))
}

#[tauri::command]
pub fn search_entries(state: State<AppState>, query: String) -> CmdResult<Vec<EntrySummaryDto>> {
    with_store(&state, |store| Ok(store.search(&query).into_iter().map(EntrySummaryDto::from).collect()))
}

#[tauri::command]
pub fn get_entry(state: State<AppState>, id: String) -> CmdResult<EntryDetailDto> {
    with_store(&state, |store| {
        let entry = store.get_entry_audited(&id).map_err(|e| e.to_string())?;
        Ok(EntryDetailDto {
            id: entry.id.to_string(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.expose().to_string(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.clone(),
            totp_seed: entry.totp_seed.as_ref().map(|s| s.expose().to_string()),
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
        })
    })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn add_entry(
    state: State<AppState>,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    totp_seed: Option<String>,
) -> CmdResult<String> {
    with_store_mut(&state, |store| {
        let id = store
            .add_entry(NewEntry {
                title,
                username: none_if_blank(username),
                password: Secret::new(password),
                url: none_if_blank(url),
                notes: none_if_blank(notes),
                tags,
                totp_seed: none_if_blank(totp_seed).map(Secret::new),
            })
            .map_err(|e| e.to_string())?;
        Ok(id.to_string())
    })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn edit_entry(
    state: State<AppState>,
    id: String,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    totp_seed: Option<String>,
) -> CmdResult<()> {
    with_store_mut(&state, |store| {
        let patch = EntryPatch {
            username: Some(none_if_blank(username)),
            password: none_if_blank(password).map(Secret::new),
            url: Some(none_if_blank(url)),
            notes: Some(none_if_blank(notes)),
            tags: Some(tags),
            totp_seed: Some(none_if_blank(totp_seed).map(Secret::new)),
        };
        store.edit_entry(&id, patch).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn remove_entry(state: State<AppState>, id: String) -> CmdResult<()> {
    with_store_mut(&state, |store| store.remove_entry(&id).map_err(|e| e.to_string()))
}

// ---------------------------------------------------------------------------------------------
// Generator / strength / TOTP
// ---------------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn generate_password(
    length: u16,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool,
) -> CmdResult<String> {
    let policy = GeneratorPolicy { length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous };
    generator::generate_password(&policy).map(|s| s.expose().to_string()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn check_all(state: State<AppState>, stale_after_days: i64) -> CmdResult<Vec<StrengthDto>> {
    with_store(&state, |store| {
        let entries = store.entries();
        let now = Utc::now();
        Ok(entries
            .iter()
            .map(|e| {
                let report = strength::assess_entry(e, entries, stale_after_days, now);
                StrengthDto {
                    id: e.id.to_string(),
                    title: e.title.clone(),
                    level: format!("{:?}", report.level),
                    estimated_bits: report.estimated_bits,
                    is_common_password: report.is_common_password,
                    reused_in: report.reused_in.iter().map(|u| u.to_string()).collect(),
                    age_days: report.age_days,
                    stale: report.stale,
                }
            })
            .collect())
    })
}

#[tauri::command]
pub fn totp_code(state: State<AppState>, id: String) -> CmdResult<(String, u64)> {
    with_store(&state, |store| {
        let entry = store.get_entry(&id).map_err(|e| e.to_string())?;
        let seed = entry.totp_seed.as_ref().ok_or_else(|| "this entry has no TOTP seed".to_string())?;
        let code = totp::current_code_now(seed.expose()).map_err(|e| e.to_string())?;
        Ok((code.code, code.seconds_remaining))
    })
}

#[tauri::command]
pub fn audit_log(state: State<AppState>, tail: usize) -> CmdResult<Vec<AuditRecordDto>> {
    with_store(&state, |store| {
        let records = store.audit().tail(tail).map_err(|e| e.to_string())?;
        Ok(records
            .into_iter()
            .map(|r| AuditRecordDto {
                ts: r.ts.to_rfc3339(),
                op: format!("{:?}", r.op),
                entry_id: r.entry_id.map(|u| u.to_string()),
            })
            .collect())
    })
}
