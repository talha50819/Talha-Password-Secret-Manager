//! Cryptographic primitives: Argon2id key derivation + XChaCha20-Poly1305 AEAD.
//!
//! See docs/01-research-and-discovery.md and docs/02-architecture.md §2.5 for the standards
//! basis (RFC 9106, OWASP Password Storage Cheat Sheet, RFC 8439) and parameter rationale.
//! This module never logs, prints, or otherwise exposes key material; the derived key is
//! always returned wrapped in `Zeroizing`.

use crate::error::{Result, VaultError};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Argon2id cost parameters. Stored per-vault in the header so a vault created under one
/// profile remains openable even if the application's defaults change later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Balanced default: comfortably above the OWASP *minimum* (19 MiB/t=2/p=1) because this
    /// cost is paid once per interactive unlock, not amortized across millions of server
    /// logins — see docs/02-architecture.md §2.5.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost_kib: 262_144, // 256 MiB
        t_cost: 3,
        p_cost: 1,
    };

    /// Faster unlock for low-memory or frequently-scripted use. Matches the OWASP documented
    /// minimum configuration.
    pub const INTERACTIVE: KdfParams = KdfParams {
        m_cost_kib: 19_456, // 19 MiB
        t_cost: 2,
        p_cost: 1,
    };

    /// Maximum-cost profile for users who prioritize brute-force resistance over unlock speed.
    pub const PARANOID: KdfParams = KdfParams {
        m_cost_kib: 1_048_576, // 1 GiB
        t_cost: 4,
        p_cost: 2,
    };

    pub fn from_profile_name(name: &str) -> Result<KdfParams> {
        match name {
            "default" => Ok(Self::DEFAULT),
            "interactive" => Ok(Self::INTERACTIVE),
            "paranoid" => Ok(Self::PARANOID),
            other => Err(VaultError::InvalidInput(format!(
                "unknown KDF profile '{other}' (expected: default, interactive, paranoid)"
            ))),
        }
    }
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .expect("OS CSPRNG is unavailable");
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .expect("OS CSPRNG is unavailable");
    nonce
}

/// Derive a 256-bit key from the master password (+ optional keyfile bytes, mixed in as the
/// Argon2 "secret" input — a second factor: possession of the keyfile is required in addition
/// to knowledge of the password) via Argon2id.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
    keyfile_bytes: Option<&[u8]>,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon2_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| VaultError::Crypto)?;

    let argon2 = match keyfile_bytes {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon2_params)
                .map_err(|_| VaultError::Crypto)?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params),
    };

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| VaultError::Crypto)?;
    Ok(out)
}

/// Encrypt `plaintext` under `key`/`nonce`, binding `aad` (the vault header bytes) so any
/// tampering with the header is detected on decrypt.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Crypto)
}

/// Decrypt and verify. Any authentication failure (wrong key, wrong/tampered AAD, tampered
/// ciphertext) returns the single generic `AuthenticationFailed` variant — see error.rs.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    let xnonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(xnonce, Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let key = [7u8; KEY_LEN];
        let nonce = random_nonce();
        let aad = b"header-bytes";
        let ct = encrypt(&key, &nonce, b"hello vault", aad).unwrap();
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(&pt[..], b"hello vault");
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = [7u8; KEY_LEN];
        let nonce = random_nonce();
        let aad = b"header-bytes";
        let mut ct = encrypt(&key, &nonce, b"hello vault", aad).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(matches!(
            decrypt(&key, &nonce, &ct, aad),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_aad_fails_closed() {
        let key = [7u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"hello vault", b"header-v1").unwrap();
        assert!(matches!(
            decrypt(&key, &nonce, &ct, b"header-v2"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let nonce = random_nonce();
        let ct = encrypt(&[1u8; KEY_LEN], &nonce, b"hello vault", b"aad").unwrap();
        assert!(matches!(
            decrypt(&[2u8; KEY_LEN], &nonce, &ct, b"aad"),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn derive_key_is_deterministic_for_same_inputs() {
        let salt = random_salt();
        let params = KdfParams::INTERACTIVE; // fast profile for test speed
        let k1 = derive_key(b"correct horse battery staple", &salt, &params, None).unwrap();
        let k2 = derive_key(b"correct horse battery staple", &salt, &params, None).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_with_different_salt() {
        let params = KdfParams::INTERACTIVE;
        let k1 = derive_key(b"same password", &random_salt(), &params, None).unwrap();
        let k2 = derive_key(b"same password", &random_salt(), &params, None).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn keyfile_bytes_change_the_derived_key() {
        let salt = random_salt();
        let params = KdfParams::INTERACTIVE;
        let k1 = derive_key(b"password", &salt, &params, None).unwrap();
        let k2 = derive_key(b"password", &salt, &params, Some(b"keyfile-bytes")).unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn salts_and_nonces_are_unique_across_calls() {
        let salts: std::collections::HashSet<_> = (0..50).map(|_| random_salt()).collect();
        let nonces: std::collections::HashSet<_> = (0..50).map(|_| random_nonce()).collect();
        assert_eq!(salts.len(), 50);
        assert_eq!(nonces.len(), 50);
    }
}
