use crate::cli_error::CliResult;
use crate::prompt;
use std::path::Path;
use vault_core::{KdfParams, VaultStore};

pub fn run(vault_path: &Path, audit_path: &Path, keyfile: Option<&Path>, kdf_profile: &str, use_stdin: bool) -> CliResult<()> {
    let params = KdfParams::from_profile_name(kdf_profile)?;
    let password = prompt::prompt_new_master_password("Master password", use_stdin)?;
    let store = VaultStore::create(vault_path, &password, keyfile, params, audit_path)?;
    store.lock();
    println!("Vault created at {}", vault_path.display());
    if keyfile.is_some() {
        println!("This vault requires its keyfile to unlock — keep it safe and separate from the vault file.");
    }
    Ok(())
}
