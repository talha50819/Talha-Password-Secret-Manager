//! CLI-local error wrapper so command handlers can use `?` freely while `main` still maps
//! back to the documented exit codes (docs/cli-reference.md: 0 ok, 1 generic, 2 usage,
//! 3 auth failure, 4 vault not found/corrupt).

use std::fmt;
use vault_core::VaultError;

#[derive(Debug)]
pub enum CliError {
    Vault(VaultError),
    Other(anyhow::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Vault(e) => write!(f, "{e}"),
            CliError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl From<VaultError> for CliError {
    fn from(e: VaultError) -> Self {
        CliError::Vault(e)
    }
}

impl From<anyhow::Error> for CliError {
    fn from(e: anyhow::Error) -> Self {
        CliError::Other(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Other(e.into())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Other(e.into())
    }
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Vault(VaultError::AuthenticationFailed) => 3,
            CliError::Vault(VaultError::NotFound)
            | CliError::Vault(VaultError::CorruptVault)
            | CliError::Vault(VaultError::UnsupportedVersion { .. }) => 4,
            CliError::Vault(_) => 1,
            CliError::Other(_) => 1,
        }
    }
}

pub type CliResult<T> = std::result::Result<T, CliError>;
