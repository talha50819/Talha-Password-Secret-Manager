//! RFC 6238 (TOTP) / RFC 4226 (HOTP) time-based one-time code generation for entries that carry
//! a stored TOTP seed. This is a *feature of the manager* (generating codes for other accounts),
//! distinct from securing the manager's own authentication.

use crate::error::{Result, VaultError};
use hmac::{Hmac, Mac};
use sha1::Sha1;

const DEFAULT_PERIOD_SECS: u64 = 30;
const DEFAULT_DIGITS: u32 = 6;

pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
}

fn decode_base32_seed(seed: &str) -> Result<Vec<u8>> {
    let cleaned: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned.to_ascii_uppercase())
        .ok_or_else(|| VaultError::InvalidInput("TOTP seed is not valid base32".into()))
}

fn hotp(key: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulus = 10u32.pow(digits);
    Ok(format!("{:0width$}", binary % modulus, width = digits as usize))
}

/// Compute the current TOTP code for `seed` (base32) at `unix_time_secs`, using the RFC 6238
/// default 30-second period and 6 digits.
pub fn current_code(seed: &str, unix_time_secs: u64) -> Result<TotpCode> {
    let key = decode_base32_seed(seed)?;
    let counter = unix_time_secs / DEFAULT_PERIOD_SECS;
    let code = hotp(&key, counter, DEFAULT_DIGITS)?;
    let seconds_remaining = DEFAULT_PERIOD_SECS - (unix_time_secs % DEFAULT_PERIOD_SECS);
    Ok(TotpCode { code, seconds_remaining })
}

pub fn current_code_now(seed: &str) -> Result<TotpCode> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs();
    current_code(seed, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vector (SHA-1, 8 digits, seed "12345678901234567890" in ASCII,
    // base32-encoded here) at T=59 -> counter=1 -> code "94287082". We use 6-digit truncation
    // of the same underlying HOTP value's known 8-digit form's low-order behavior is algorithm-
    // specific, so we instead assert against a seed we control end-to-end and check determinism
    // and time-window boundaries, which is what the vault actually depends on.

    #[test]
    fn same_time_window_yields_same_code() {
        let seed = "JBSWY3DPEHPK3PXP"; // arbitrary valid base32 seed
        let c1 = current_code(seed, 1_000_000).unwrap();
        let c2 = current_code(seed, 1_000_010).unwrap();
        assert_eq!(c1.code, c2.code);
    }

    #[test]
    fn crossing_a_period_boundary_changes_the_code() {
        let seed = "JBSWY3DPEHPK3PXP";
        let c1 = current_code(seed, 1_000_000).unwrap(); // window start
        let c2 = current_code(seed, 1_000_030).unwrap(); // next window
        assert_ne!(c1.code, c2.code);
    }

    #[test]
    fn code_is_always_six_digits() {
        let seed = "JBSWY3DPEHPK3PXP";
        for t in [0u64, 1, 59, 60, 1_700_000_000] {
            let c = current_code(seed, t).unwrap();
            assert_eq!(c.code.len(), 6);
            assert!(c.code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn seconds_remaining_counts_down_within_a_window() {
        let seed = "JBSWY3DPEHPK3PXP";
        let c1 = current_code(seed, 0).unwrap(); // exact window start
        let c2 = current_code(seed, 10).unwrap(); // 10s into the same window
        assert_eq!(c1.seconds_remaining, 30);
        assert_eq!(c2.seconds_remaining, 20);
    }

    #[test]
    fn invalid_base32_seed_is_rejected() {
        assert!(current_code("not-valid-base32!!", 0).is_err());
    }

    #[test]
    fn rfc4226_test_vector_hotp_sha1_6_digits() {
        // RFC 4226 Appendix D: secret ASCII "12345678901234567890", counters 0..9.
        let key = b"12345678901234567890";
        let expected = ["755224", "287082", "359152", "969429", "338314"];
        for (counter, exp) in expected.iter().enumerate() {
            let code = hotp(key, counter as u64, 6).unwrap();
            assert_eq!(&code, exp, "counter {counter}");
        }
    }
}
