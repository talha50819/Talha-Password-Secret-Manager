//! Error types.
//!
//! Design rule (threat model T9 — see docs/03-threat-model.md): `Display` messages returned to
//! the CLI layer are deliberately low-information so a failed unlock never reveals *which*
//! internal check tripped. The full source chain (via `std::error::Error::source`) is still
//! available for an explicit `--debug` diagnostic path, but the default path never surfaces it.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("authentication failed: incorrect master password, missing/incorrect keyfile, or a corrupted vault")]
    AuthenticationFailed,

    #[error("no vault found at the given path")]
    NotFound,

    #[error("a vault already exists at the given path")]
    AlreadyExists,

    #[error("vault file is not a recognized vault, or is corrupt")]
    CorruptVault,

    #[error("unsupported vault format version {found} (this build supports version {supported})")]
    UnsupportedVersion { found: u16, supported: u16 },

    #[error("no entry matches '{0}'")]
    EntryNotFound(String),

    #[error("an entry titled '{0}' already exists")]
    DuplicateTitle(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("a keyfile is required to open this vault")]
    KeyfileRequired,

    #[error("vault is locked by another vaultkeep process (if you're sure no other process is using it, remove '{0}')")]
    Locked(String),

    #[error("I/O error")]
    Io(#[source] std::io::Error),

    #[error("internal cryptographic operation failed")]
    Crypto,

    #[error("internal serialization error")]
    Serialization,
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;
