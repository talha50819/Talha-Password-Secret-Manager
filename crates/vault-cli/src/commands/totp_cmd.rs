use crate::cli_error::CliResult;
use vault_core::{VaultError, VaultStore};

pub fn run(store: &VaultStore, title: &str) -> CliResult<()> {
    let entry = store.get_entry_audited(title)?;
    let seed = entry
        .totp_seed
        .as_ref()
        .ok_or_else(|| VaultError::InvalidInput("this entry has no TOTP seed".into()))?;
    let code = vault_core::totp::current_code_now(seed.expose())?;
    println!("{}  (expires in {}s)", code.code, code.seconds_remaining);
    Ok(())
}
