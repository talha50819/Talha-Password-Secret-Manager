//! On-disk vault envelope: a cleartext, CRC-checked header (also used as AEAD associated data)
//! followed by the AEAD ciphertext. See docs/data-model.md for the authoritative field table
//! and docs/02-architecture.md §2.4.1 for the rationale.

use crate::crypto::{KdfParams, NONCE_LEN, SALT_LEN};
use crate::error::{Result, VaultError};
use std::fs;
use std::io::Write;
use std::path::Path;

pub const MAGIC: [u8; 4] = *b"VKLT";
pub const CURRENT_FORMAT_VERSION: u16 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const AEAD_XCHACHA20POLY1305: u8 = 1;

pub const HEADER_LEN: usize = 4 + 2 + 1 + SALT_LEN + 4 + 4 + 4 + 1 + 1 + NONCE_LEN + 4; // 65

#[derive(Debug, Clone)]
pub struct Header {
    pub format_version: u16,
    pub kdf_id: u8,
    pub kdf_salt: [u8; SALT_LEN],
    pub kdf_params: KdfParams,
    pub keyfile_bound: bool,
    pub aead_id: u8,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn new(kdf_salt: [u8; SALT_LEN], kdf_params: KdfParams, keyfile_bound: bool, nonce: [u8; NONCE_LEN]) -> Self {
        Header {
            format_version: CURRENT_FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            kdf_salt,
            kdf_params,
            keyfile_bound,
            aead_id: AEAD_XCHACHA20POLY1305,
            nonce,
        }
    }

    /// Serialize to the fixed-size on-disk representation, including the trailing CRC32.
    /// This byte string is also used verbatim as the AEAD associated data (AAD), so any
    /// tampering with a header field is caught by AEAD tag verification, not just the CRC.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        let mut w = &mut buf[..];
        w.write_all(&MAGIC).unwrap();
        w.write_all(&self.format_version.to_le_bytes()).unwrap();
        w.write_all(&[self.kdf_id]).unwrap();
        w.write_all(&self.kdf_salt).unwrap();
        w.write_all(&self.kdf_params.m_cost_kib.to_le_bytes()).unwrap();
        w.write_all(&self.kdf_params.t_cost.to_le_bytes()).unwrap();
        w.write_all(&self.kdf_params.p_cost.to_le_bytes()).unwrap();
        w.write_all(&[self.keyfile_bound as u8]).unwrap();
        w.write_all(&[self.aead_id]).unwrap();
        w.write_all(&self.nonce).unwrap();

        let crc = crc32fast::hash(&buf[..HEADER_LEN - 4]);
        buf[HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(VaultError::CorruptVault);
        }
        if buf[0..4] != MAGIC {
            return Err(VaultError::CorruptVault);
        }
        let expected_crc = crc32fast::hash(&buf[..HEADER_LEN - 4]);
        let stored_crc = u32::from_le_bytes(buf[HEADER_LEN - 4..HEADER_LEN].try_into().unwrap());
        if expected_crc != stored_crc {
            return Err(VaultError::CorruptVault);
        }

        let format_version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if format_version != CURRENT_FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion {
                found: format_version,
                supported: CURRENT_FORMAT_VERSION,
            });
        }
        let kdf_id = buf[6];
        let mut kdf_salt = [0u8; SALT_LEN];
        kdf_salt.copy_from_slice(&buf[7..7 + SALT_LEN]);
        let mut off = 7 + SALT_LEN;
        let m_cost_kib = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let t_cost = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let p_cost = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let keyfile_bound = buf[off] != 0;
        off += 1;
        let aead_id = buf[off];
        off += 1;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[off..off + NONCE_LEN]);

        Ok(Header {
            format_version,
            kdf_id,
            kdf_salt,
            kdf_params: KdfParams { m_cost_kib, t_cost, p_cost },
            keyfile_bound,
            aead_id,
            nonce,
        })
    }
}

/// Write `header || ciphertext` atomically: write to a sibling temp file, `fsync`, then rename
/// over the destination. Rename is atomic on NTFS/APFS/most Linux filesystems for same-directory
/// same-filesystem renames, so a crash mid-write can never leave a half-written vault at `path`.
pub fn write_vault_atomic(path: &Path, header: &Header, ciphertext: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or(VaultError::InvalidInput("vault path has no parent directory".into()))?;
    fs::create_dir_all(dir)?;

    let tmp_path = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("vault"),
        std::process::id()
    ));

    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&header.to_bytes())?;
        f.write_all(ciphertext)?;
        f.sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Path of the advisory lock file for a given vault path (VAPT finding V-11, docs/08-vapt-report.md).
pub fn lock_path_for(vault_path: &Path) -> std::path::PathBuf {
    let mut p = vault_path.to_path_buf();
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("vault").to_string();
    p.set_file_name(format!("{name}.lock"));
    p
}

/// Acquire a simple, cross-process advisory lock: atomically create a sibling `.lock` file
/// (`O_EXCL`-style — fails if it already exists) and record this process's PID in it for
/// diagnosability. This does not prevent every possible race (a hard-killed process leaves a
/// stale lock behind — documented in docs/09-performance-and-reliability.md §9.3), but it does
/// close the common case of two `vaultkeep` invocations against the same vault overlapping.
pub fn acquire_lock(vault_path: &Path) -> Result<std::path::PathBuf> {
    let lock_path = lock_path_for(vault_path);
    if let Some(dir) = lock_path.parent() {
        fs::create_dir_all(dir)?;
    }
    match fs::OpenOptions::new().write(true).create_new(true).open(&lock_path) {
        Ok(mut f) => {
            let _ = write!(f, "{}", std::process::id());
            Ok(lock_path)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(VaultError::Locked(lock_path.display().to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn release_lock(lock_path: &Path) {
    let _ = fs::remove_file(lock_path);
}

pub fn read_vault(path: &Path) -> Result<(Header, Vec<u8>)> {
    if !path.exists() {
        return Err(VaultError::NotFound);
    }
    let bytes = fs::read(path)?;
    if bytes.len() < HEADER_LEN {
        return Err(VaultError::CorruptVault);
    }
    let header = Header::from_bytes(&bytes[..HEADER_LEN])?;
    let ciphertext = bytes[HEADER_LEN..].to_vec();
    Ok((header, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{random_nonce, random_salt};
    use tempfile::tempdir;

    fn sample_header() -> Header {
        Header::new(random_salt(), KdfParams::DEFAULT, false, random_nonce())
    }

    #[test]
    fn header_round_trips_through_bytes() {
        let h = sample_header();
        let bytes = h.to_bytes();
        let h2 = Header::from_bytes(&bytes).unwrap();
        assert_eq!(h.format_version, h2.format_version);
        assert_eq!(h.kdf_salt, h2.kdf_salt);
        assert_eq!(h.kdf_params, h2.kdf_params);
        assert_eq!(h.nonce, h2.nonce);
    }

    #[test]
    fn corrupted_header_byte_is_rejected() {
        let h = sample_header();
        let mut bytes = h.to_bytes();
        bytes[10] ^= 0xFF; // inside kdf_salt
        assert!(matches!(Header::from_bytes(&bytes), Err(VaultError::CorruptVault)));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut bytes = sample_header().to_bytes();
        bytes[0] = b'X';
        assert!(matches!(Header::from_bytes(&bytes), Err(VaultError::CorruptVault)));
    }

    #[test]
    fn atomic_write_then_read_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.vkl");
        let header = sample_header();
        write_vault_atomic(&path, &header, b"fake-ciphertext").unwrap();
        let (h2, ct) = read_vault(&path).unwrap();
        assert_eq!(h2.kdf_salt, header.kdf_salt);
        assert_eq!(ct, b"fake-ciphertext");
    }

    #[test]
    fn missing_file_returns_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.vkl");
        assert!(matches!(read_vault(&path), Err(VaultError::NotFound)));
    }

    #[test]
    fn no_leftover_temp_file_after_successful_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.vkl");
        write_vault_atomic(&path, &sample_header(), b"data").unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
