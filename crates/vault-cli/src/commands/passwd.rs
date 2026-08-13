use crate::cli_error::CliResult;
use crate::prompt;
use std::path::Path;
use vault_core::VaultStore;

pub fn run(store: &mut VaultStore, keyfile: Option<&Path>, use_stdin: bool) -> CliResult<()> {
    println!("Changing the master password re-encrypts the entire vault under a new key.");
    let new_password = prompt::prompt_new_master_password("New master password", use_stdin)?;
    store.rekey(&new_password, None, keyfile)?;
    println!("Master password changed.");
    Ok(())
}
