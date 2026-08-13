//! Clipboard copy with hash-guarded auto-clear (docs/04-backlog.md US-3.1, threat model T8).
//!
//! Clipboard access can fail in headless/CI environments (no display server on Linux, no
//! interactive session, etc.) — that must never be treated as a hard error for a security tool,
//! so failures here are reported to the caller as a plain `bool`/message rather than panicking.

use sha2::{Digest, Sha256};
use std::thread;
use std::time::Duration;

fn hash_of(s: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

/// Copy `value` to the system clipboard and, on a background thread, clear it again after
/// `clear_after` — but only if the clipboard still holds exactly what we put there (a SHA-256
/// comparison, not a plaintext comparison held in the thread's closure any longer than
/// necessary), so a manual copy the user makes in the meantime is never clobbered.
pub fn copy_with_autoclear(value: &str, clear_after: Duration) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
    clipboard.set_text(value).map_err(|e| format!("failed to set clipboard: {e}"))?;

    let expected_hash = hash_of(value);
    thread::spawn(move || {
        thread::sleep(clear_after);
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            if let Ok(current) = clipboard.get_text() {
                if hash_of(&current) == expected_hash {
                    let _ = clipboard.set_text(String::new());
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_distinguishes_values() {
        assert_eq!(hash_of("abc"), hash_of("abc"));
        assert_ne!(hash_of("abc"), hash_of("abd"));
    }
}
