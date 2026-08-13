//! CSPRNG-backed password generator. See docs/04-backlog.md US-2.2.1.

use crate::error::{Result, VaultError};
use crate::model::GeneratorPolicy;
use crate::secret::Secret;
use rand::seq::SliceRandom;
use rand::Rng as _;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/~";
/// Characters that are easy to confuse in most fonts: 0/O, 1/l/I, etc.
const AMBIGUOUS: &[u8] = b"0O1lI|";

fn build_charset(policy: &GeneratorPolicy) -> Result<Vec<u8>> {
    let mut set = Vec::new();
    if policy.use_upper {
        set.extend_from_slice(UPPER);
    }
    if policy.use_lower {
        set.extend_from_slice(LOWER);
    }
    if policy.use_digits {
        set.extend_from_slice(DIGITS);
    }
    if policy.use_symbols {
        set.extend_from_slice(SYMBOLS);
    }
    if policy.avoid_ambiguous {
        set.retain(|c| !AMBIGUOUS.contains(c));
    }
    if set.is_empty() {
        return Err(VaultError::InvalidInput(
            "generator policy selects no character classes".into(),
        ));
    }
    Ok(set)
}

/// Class pools used to guarantee at least one character from each *requested* class appears.
fn requested_class_pools(policy: &GeneratorPolicy) -> Vec<Vec<u8>> {
    let filter = |set: &[u8]| -> Vec<u8> {
        set.iter().copied().filter(|c| !(policy.avoid_ambiguous && AMBIGUOUS.contains(c))).collect()
    };
    let mut pools = Vec::new();
    if policy.use_upper {
        pools.push(filter(UPPER));
    }
    if policy.use_lower {
        pools.push(filter(LOWER));
    }
    if policy.use_digits {
        pools.push(filter(DIGITS));
    }
    if policy.use_symbols {
        pools.push(filter(SYMBOLS));
    }
    pools
}

pub fn generate_password(policy: &GeneratorPolicy) -> Result<Secret> {
    if policy.length < 4 {
        return Err(VaultError::InvalidInput("password length must be at least 4".into()));
    }
    let charset = build_charset(policy)?;
    let pools = requested_class_pools(policy);
    if pools.len() > policy.length as usize {
        return Err(VaultError::InvalidInput(
            "password length too short to include one of every requested character class".into(),
        ));
    }

    // `rand::rng()` is a cryptographically-secure generator (ChaCha), automatically and
    // periodically reseeded from OS entropy — the standard choice for this kind of repeated
    // sampling, where re-opening the raw OS RNG on every draw would be wasteful.
    let mut rng = rand::rng();
    let mut chars: Vec<u8> = Vec::with_capacity(policy.length as usize);

    // Guarantee at least one char from each requested class.
    for pool in &pools {
        let idx = rng.random_range(0..pool.len());
        chars.push(pool[idx]);
    }
    // Fill the remainder from the full combined charset.
    while chars.len() < policy.length as usize {
        let idx = rng.random_range(0..charset.len());
        chars.push(charset[idx]);
    }

    // Shuffle so the guaranteed class characters aren't always in the first N positions.
    chars.shuffle(&mut rng);

    let s = String::from_utf8(chars).expect("charset is ASCII by construction");
    Ok(Secret::new(s))
}

pub fn generate_many(policy: &GeneratorPolicy, count: usize) -> Result<Vec<Secret>> {
    (0..count).map(|_| generate_password(policy)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_length() {
        let policy = GeneratorPolicy::default();
        let pw = generate_password(&policy).unwrap();
        assert_eq!(pw.expose().len(), policy.length as usize);
    }

    #[test]
    fn respects_character_class_restriction_to_digits_only() {
        let policy = GeneratorPolicy {
            length: 12,
            use_upper: false,
            use_lower: false,
            use_digits: true,
            use_symbols: false,
            avoid_ambiguous: false,
        };
        let pw = generate_password(&policy).unwrap();
        assert!(pw.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn avoids_ambiguous_characters_when_requested() {
        let policy = GeneratorPolicy { length: 200, ..GeneratorPolicy::default() };
        let pw = generate_password(&policy).unwrap();
        assert!(pw.expose().bytes().all(|b| !AMBIGUOUS.contains(&b)));
    }

    #[test]
    fn rejects_no_character_classes() {
        let policy = GeneratorPolicy {
            use_upper: false,
            use_lower: false,
            use_digits: false,
            use_symbols: false,
            ..GeneratorPolicy::default()
        };
        assert!(generate_password(&policy).is_err());
    }

    #[test]
    fn generated_passwords_are_not_all_identical() {
        let policy = GeneratorPolicy::default();
        let passwords = generate_many(&policy, 20).unwrap();
        let unique: std::collections::HashSet<_> = passwords.iter().map(|p| p.expose().to_owned()).collect();
        assert_eq!(unique.len(), 20, "expected 20 distinct passwords from a CSPRNG generator");
    }

    #[test]
    fn includes_at_least_one_char_from_every_requested_class() {
        let policy = GeneratorPolicy { length: 8, ..GeneratorPolicy::default() };
        for _ in 0..50 {
            let pw = generate_password(&policy).unwrap();
            let s = pw.expose();
            assert!(s.bytes().any(|b| UPPER.contains(&b)));
            assert!(s.bytes().any(|b| LOWER.contains(&b)));
            assert!(s.bytes().any(|b| DIGITS.contains(&b)));
            assert!(s.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }
}
