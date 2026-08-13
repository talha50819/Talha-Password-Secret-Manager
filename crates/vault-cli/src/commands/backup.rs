use crate::cli_error::{CliError, CliResult};
use crate::prompt;
use std::path::Path;
use vault_core::{AuditOp, NewEntry, VaultError, VaultStore};

pub fn export(store: &VaultStore, output: &Path, plaintext_json: bool, i_understand_the_risk: bool) -> CliResult<()> {
    if plaintext_json {
        if !i_understand_the_risk {
            return Err(CliError::from(VaultError::InvalidInput(
                "plaintext export requires --i-understand-the-risk".into(),
            )));
        }
        eprintln!("WARNING: writing every stored secret to disk in PLAINTEXT at {}", output.display());
        let json = serde_json::to_string_pretty(store.entries())?;
        std::fs::write(output, json)?;
    } else {
        std::fs::copy(store.path(), output)?;
    }
    store.audit().log(AuditOp::Export, None)?;
    println!("Exported vault to {}", output.display());
    Ok(())
}

pub fn import(store: &mut VaultStore, import_path: &Path, merge: bool, use_stdin: bool) -> CliResult<()> {
    println!("Enter the master password for the backup file being imported.");
    let backup_password = prompt::prompt_password("Backup master password", use_stdin)?;
    let backup_audit_path = import_path.with_extension("import-tmp.audit.log");
    let backup_store = VaultStore::open(import_path, &backup_password, None, &backup_audit_path)?;

    if !merge {
        let ids: Vec<String> = store.list(None).into_iter().map(|s| s.id.to_string()).collect();
        for id in ids {
            store.remove_entry(&id)?;
        }
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for entry in backup_store.entries() {
        let new_entry = NewEntry {
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.clone(),
            totp_seed: entry.totp_seed.clone(),
        };
        match store.add_entry(new_entry) {
            Ok(_) => imported += 1,
            Err(VaultError::DuplicateTitle(_)) => skipped += 1,
            Err(e) => return Err(e.into()),
        }
    }

    let _ = std::fs::remove_file(&backup_audit_path);
    store.audit().log(AuditOp::Import, None)?;
    println!("Imported {imported} entr{suffix}, skipped {skipped} duplicate title(s).", suffix = if imported == 1 { "y" } else { "ies" });
    Ok(())
}
