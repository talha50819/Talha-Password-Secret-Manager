//! Interactive `shell` session with idle-based auto-lock (docs/04-backlog.md US-3.2, threat
//! model T14). The unlocked `VaultStore` lives behind a mutex shared with a watchdog thread;
//! once the idle timeout elapses the watchdog takes the store out and drops it, which zeroizes
//! its key material — the next command must re-authenticate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct IdleSession<T> {
    inner: Arc<Mutex<Option<T>>>,
    last_activity_unix: Arc<AtomicU64>,
    timeout: Duration,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl<T: Send + 'static> IdleSession<T> {
    pub fn new(value: T, timeout: Duration) -> Self {
        let session = IdleSession {
            inner: Arc::new(Mutex::new(Some(value))),
            last_activity_unix: Arc::new(AtomicU64::new(now_unix())),
            timeout,
        };
        session.spawn_watchdog();
        session
    }

    fn spawn_watchdog(&self) {
        let inner = Arc::clone(&self.inner);
        let last_activity = Arc::clone(&self.last_activity_unix);
        let timeout_secs = self.timeout.as_secs().max(1);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let idle_for = now_unix().saturating_sub(last_activity.load(Ordering::Relaxed));
            if idle_for >= timeout_secs {
                let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                if guard.is_some() {
                    *guard = None; // drop the value here: zeroizes key material
                }
            }
        });
    }

    /// Record activity (resets the idle clock) and run `f` against the unlocked value, or
    /// `None` if the session has auto-locked and needs re-authentication.
    pub fn touch_and_use<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.last_activity_unix.store(now_unix(), Ordering::Relaxed);
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_mut().map(f)
    }

    pub fn is_locked(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).is_none()
    }

    /// Replace the session contents (e.g. after re-authenticating post-lock).
    pub fn unlock_with(&self, value: T) {
        self.last_activity_unix.store(now_unix(), Ordering::Relaxed);
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
    }

    /// Explicit immediate lock, independent of the idle timer.
    pub fn lock_now(&self) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_and_use_runs_against_the_live_value() {
        let session = IdleSession::new(41, Duration::from_secs(60));
        let result = session.touch_and_use(|v| {
            *v += 1;
            *v
        });
        assert_eq!(result, Some(42));
    }

    #[test]
    fn session_auto_locks_after_idle_timeout() {
        let session = IdleSession::new(1, Duration::from_secs(1));
        assert!(!session.is_locked());
        // wait past the 1s timeout + the watchdog's 1s poll tick
        std::thread::sleep(Duration::from_millis(2500));
        assert!(session.is_locked());
        assert_eq!(session.touch_and_use(|v| *v), None);
    }

    #[test]
    fn explicit_lock_and_unlock_work() {
        let session = IdleSession::new(1, Duration::from_secs(60));
        session.lock_now();
        assert!(session.is_locked());
        session.unlock_with(99);
        assert_eq!(session.touch_and_use(|v| *v), Some(99));
    }

}
