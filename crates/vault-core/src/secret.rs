//! A small, dependency-free "secret string" wrapper.
//!
//! Deliberately hand-rolled instead of pulling in a generic secrecy crate: this gives us full
//! control over exactly the guarantees the threat model ([docs/03-threat-model.md] T6/T9/T10)
//! promises — redacted `Debug`/`Display`, best-effort zeroization on drop, and constant-time
//! equality — and keeps those guarantees easy to unit-test directly against this type.

use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A string that is never printed and is zeroized when dropped.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Secret(String);

const REDACTED: &str = "***REDACTED***";

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// Explicit, deliberately-named accessor — every call site that reaches for the real
    /// value is greppable, which is the point (nothing should do it by accident).
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}
impl Eq for Secret {}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Secret(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_never_leak_the_value() {
        let s = Secret::new("hunter2-super-secret");
        let debug = format!("{s:?}");
        let display = format!("{s}");
        assert!(!debug.contains("hunter2"));
        assert!(!display.contains("hunter2"));
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
    }

    #[test]
    fn equality_is_value_based() {
        assert_eq!(Secret::new("abc"), Secret::new("abc"));
        assert_ne!(Secret::new("abc"), Secret::new("abd"));
    }

    #[test]
    fn expose_returns_the_real_value() {
        assert_eq!(Secret::new("abc").expose(), "abc");
    }
}
