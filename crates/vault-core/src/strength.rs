//! Local, offline password strength estimation.
//!
//! Deliberately does **not** call out to any online breach-check service by default — the
//! project's threat model commits to zero network I/O in the default path (see
//! docs/01-research-and-discovery.md §1.2, docs/03-threat-model.md). This gives a coarse but
//! useful entropy estimate plus a small embedded common-password blocklist and cross-entry
//! reuse/age detection, which covers the majority of real-world weak-master-password risk
//! (NIST SP 800-63B explicitly recommends blocklist checks over forced complexity rules).

use crate::model::Entry;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// A small, embedded sample of extremely common passwords (top of most published breach
/// corpora). This is intentionally not exhaustive — it catches the worst offenders offline;
/// a larger corpus (e.g. HIBP's Pwned Passwords via k-anonymity) is a documented, opt-in,
/// network-touching roadmap item (see docs/12-production-readiness.md).
const COMMON_PASSWORDS: &[&str] = &[
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "password1",
    "111111", "123123", "admin", "letmein", "welcome", "monkey", "dragon", "iloveyou", "1234567",
    "sunshine", "master", "football", "shadow", "superman", "trustno1", "princess", "qwertyuiop",
    "passw0rd", "starwars", "freedom", "whatever", "qazwsx", "michael", "jennifer", "changeme",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum StrengthLevel {
    VeryWeak,
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

#[derive(Debug, Clone, Serialize)]
pub struct StrengthReport {
    pub level: StrengthLevel,
    pub estimated_bits: f64,
    pub is_common_password: bool,
    pub reused_in: Vec<uuid::Uuid>,
    pub age_days: Option<i64>,
    pub stale: bool,
}

/// Estimate entropy from the *character classes actually observed*, which is a defensible
/// lower bound: log2(observed_charset_size) * length. This intentionally does not attempt
/// full statistical/dictionary modeling (e.g. zxcvbn-style) — that is out of scope for the
/// MVP and documented as a roadmap enhancement.
pub fn estimate_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

    let mut pool_size: u32 = 0;
    if has_lower {
        pool_size += 26;
    }
    if has_upper {
        pool_size += 26;
    }
    if has_digit {
        pool_size += 10;
    }
    if has_symbol {
        pool_size += 33;
    }
    if pool_size == 0 {
        pool_size = 1;
    }

    let len = password.chars().count() as f64;
    len * (pool_size as f64).log2()
}

fn level_from_bits(bits: f64, is_common: bool) -> StrengthLevel {
    if is_common {
        return StrengthLevel::VeryWeak;
    }
    match bits {
        b if b < 28.0 => StrengthLevel::VeryWeak,
        b if b < 36.0 => StrengthLevel::Weak,
        b if b < 60.0 => StrengthLevel::Moderate,
        b if b < 80.0 => StrengthLevel::Strong,
        _ => StrengthLevel::VeryStrong,
    }
}

pub fn is_common_password(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    COMMON_PASSWORDS.contains(&lower.as_str())
}

/// Validate a *master* password against NIST SP 800-63B 5.1.1.1/5.1.1.2: reject below the
/// 8-character minimum, and reject values found on a common/compromised-password list (the
/// guideline's "SHALL compare... and require the subscriber to choose a different value"
/// clause) — see docs/11-compliance-mapping.md R-1/R-2. Deliberately does **not** impose any
/// composition/character-class rule, matching the same standard's explicit recommendation
/// against forced complexity.
pub fn validate_master_password(password: &str) -> crate::error::Result<()> {
    if password.chars().count() < 8 {
        return Err(crate::error::VaultError::InvalidInput(
            "master password must be at least 8 characters (NIST SP 800-63B)".into(),
        ));
    }
    if is_common_password(password) {
        return Err(crate::error::VaultError::InvalidInput(
            "this master password is far too common/predictable — choose a different one".into(),
        ));
    }
    Ok(())
}

/// Produce a strength report for a single entry in the context of the whole vault (needed for
/// reuse detection) and an optional staleness threshold in days.
pub fn assess_entry(entry: &Entry, all_entries: &[Entry], stale_after_days: i64, now: DateTime<Utc>) -> StrengthReport {
    let pw = entry.password.expose();
    let bits = estimate_bits(pw);
    let common = is_common_password(pw);

    let reused_in: Vec<uuid::Uuid> = all_entries
        .iter()
        .filter(|other| other.id != entry.id && other.password == entry.password)
        .map(|other| other.id)
        .collect();

    let age_days = Some((now - entry.updated_at).num_days());
    let stale = age_days.map(|d| d >= stale_after_days).unwrap_or(false);

    StrengthReport {
        level: level_from_bits(bits, common),
        estimated_bits: bits,
        is_common_password: common,
        reused_in,
        age_days,
        stale,
    }
}

/// Convenience: map of entry id -> report, for `vaultkeep check --all`.
pub fn assess_all(entries: &[Entry], stale_after_days: i64, now: DateTime<Utc>) -> HashMap<uuid::Uuid, StrengthReport> {
    entries
        .iter()
        .map(|e| (e.id, assess_entry(e, entries, stale_after_days, now)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use uuid::Uuid;

    fn entry(password: &str, updated_days_ago: i64) -> Entry {
        let now = Utc::now();
        Entry {
            id: Uuid::new_v4(),
            title: "t".into(),
            username: None,
            password: Secret::new(password),
            url: None,
            notes: None,
            tags: vec![],
            totp_seed: None,
            custom_fields: vec![],
            password_history: vec![],
            created_at: now,
            updated_at: now - chrono::Duration::days(updated_days_ago),
        }
    }

    #[test]
    fn common_password_is_flagged_very_weak() {
        let e = entry("password1", 0);
        let report = assess_entry(&e, std::slice::from_ref(&e), 365, Utc::now());
        assert!(report.is_common_password);
        assert_eq!(report.level, StrengthLevel::VeryWeak);
    }

    #[test]
    fn long_random_password_is_strong() {
        let e = entry("qX7!vM2#pL9$rT4@wZ6&", 0);
        let report = assess_entry(&e, std::slice::from_ref(&e), 365, Utc::now());
        assert!(report.level >= StrengthLevel::Strong);
    }

    #[test]
    fn reuse_is_detected_across_entries() {
        let e1 = entry("SharedPassw0rd!", 0);
        let mut e2 = entry("SharedPassw0rd!", 0);
        e2.id = Uuid::new_v4();
        let all = vec![e1.clone(), e2.clone()];
        let report = assess_entry(&e1, &all, 365, Utc::now());
        assert_eq!(report.reused_in, vec![e2.id]);
    }

    #[test]
    fn staleness_is_detected() {
        let e = entry("qX7!vM2#pL9$rT4@wZ6&", 400);
        let report = assess_entry(&e, std::slice::from_ref(&e), 365, Utc::now());
        assert!(report.stale);
    }

    #[test]
    fn empty_password_has_zero_entropy() {
        assert_eq!(estimate_bits(""), 0.0);
    }

    #[test]
    fn validate_master_password_rejects_short_passwords() {
        assert!(validate_master_password("short1").is_err()); // 6 chars
        assert!(validate_master_password("exactly8").is_ok()); // 8 chars, not common
    }

    #[test]
    fn validate_master_password_rejects_common_passwords_even_if_long_enough() {
        assert!(validate_master_password("password1").is_err());
    }

    #[test]
    fn validate_master_password_accepts_a_reasonable_passphrase() {
        assert!(validate_master_password("correct horse battery staple").is_ok());
    }
}
