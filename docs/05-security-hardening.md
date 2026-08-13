# Phase 5/6 — Security Engineering & Hardening Report

This documents the concrete controls implemented and hardening decisions made, mapped back to
the threat model ([03-threat-model.md](03-threat-model.md)) and standards
([01-research-and-discovery.md](01-research-and-discovery.md)). Every decision below is either
implemented in code (file/line referenced) or explicitly recorded as an accepted/deferred risk —
nothing is asserted without a concrete mechanism.

## 5.1 Cryptographic Controls

| Control | Implementation | Standard basis |
|---|---|---|
| Password-based key derivation | Argon2id, default m=256 MiB/t=3/p=1, per-vault-configurable (`default`/`interactive`/`paranoid` profiles) | RFC 9106, OWASP Password Storage Cheat Sheet — [crypto.rs](../crates/vault-core/src/crypto.rs) |
| Authenticated encryption at rest | XChaCha20-Poly1305, random 192-bit nonce per write, header bound as AAD | RFC 8439 — [crypto.rs](../crates/vault-core/src/crypto.rs) |
| Random number generation | OS CSPRNG (`OsRng` via `TryRngCore`) for salts/nonces/key material; `rand::rng()` (ChaCha, OS-reseeded) for generator sampling/shuffling | — |
| Constant-time comparison | `subtle::ConstantTimeEq` used for `Secret` equality (reuse detection, keyfile-derived checks) | Avoids timing side channels on secret comparison |
| Fail-closed authentication | A single `VaultError::AuthenticationFailed` is returned for *any* decryption failure (wrong password, wrong keyfile, tampered ciphertext, tampered header) | Threat model T1/T2/T9 — [store.rs](../crates/vault-core/src/store.rs), tested in `store::tests::wrong_password_fails_closed`, `tampered_vault_file_refuses_to_open` |
| No custom cryptography | Every primitive comes from an independently maintained, widely used crate (RustCrypto `argon2`, `chacha20poly1305`, `hmac`, `sha1`/`sha2`) — nothing hand-rolled | Standard secure-coding guidance: never implement your own crypto primitives |

## 5.2 Secret Hygiene

- `Secret` ([secret.rs](../crates/vault-core/src/secret.rs)) is a hand-rolled, dependency-minimal
  wrapper (not a generic secrecy crate) so its guarantees are exactly what the threat model
  promises and are directly unit-tested:
  - `Debug`/`Display` always print `***REDACTED***`, never the value — test:
    `secret::tests::debug_and_display_never_leak_the_value`.
  - `Drop` zeroizes the underlying `String` (`zeroize::Zeroize`).
  - Equality is constant-time.
- The derived vault key is held in `zeroize::Zeroizing<[u8; 32]>`, scrubbed on drop, and is
  never passed to any logging, `Debug`, or error-message path.
- End-to-end enforcement test: `store::tests::audit_log_never_contains_secret_values_or_titles`
  and CLI-level `audit_log_never_contains_plaintext_secrets_or_titles` in
  `crates/vault-cli/tests/cli.rs` assert that titles, usernames, and password values never
  appear in the audit log file byte stream — this is checked against the *actual persisted
  file*, not just the in-memory type, closing the gap between "the type is safe" and "the
  feature is safe."
- `list`/`search` return `EntrySummary`, a struct with no field capable of holding a password,
  TOTP seed, or sensitive custom field — leaking a secret through those paths is a compile-time
  impossibility (verified by `store::tests::list_and_search_never_expose_passwords` and the CLI
  integration test `list_json_is_valid_json_and_excludes_passwords`).

## 5.3 Session & Input Hardening

- **No `--password` CLI flag.** Secrets are only ever accepted via a hidden interactive prompt
  (`rpassword`) or, for scripted/CI use, an explicit `--stdin` opt-in that reads one line —
  documented as a sensitive-use mode, never the default (threat model T7).
- **Shell auto-lock.** `vaultkeep shell` holds the unlocked `VaultStore` behind an
  `IdleSession` ([session.rs](../crates/vault-cli/src/session.rs)) with a background watchdog
  thread; after `session_idle_timeout_seconds` (default 300s) of inactivity the store is
  dropped (zeroizing its key) and the next command requires re-authentication — tested in
  `session::tests::session_auto_locks_after_idle_timeout`.
- **Clipboard auto-clear.** Copy operations hash what was written and only clear the clipboard
  after the timeout if it still contains that exact value, so a later manual copy is never
  clobbered ([clipboard.rs](../crates/vault-cli/src/clipboard.rs)).
- **Generic error messages.** CLI-facing `Display` text never reveals which internal check
  failed; full detail is available only behind an explicit `--debug` flag
  ([main.rs](../crates/vault-cli/src/main.rs) `print_debug_chain`).

## 5.4 File System Hardening

- **Atomic writes.** The vault is always written to a sibling temp file, `fsync`'d, then
  renamed over the destination — a crash mid-write can never leave a corrupted vault at the
  real path ([format.rs](../crates/vault-core/src/format.rs), tested in
  `format::tests::atomic_write_then_read_round_trip` and `no_leftover_temp_file_after_successful_write`).
- **Restrictive permissions (Unix).** The vault file and audit log are written with `0600`
  (owner read/write only) via `std::os::unix::fs::PermissionsExt`.
- **Windows.** NTFS ACLs default to the owning user's profile permissions under
  `%APPDATA%`; explicit ACL tightening (`icacls`) is a documented roadmap item (see
  [12-production-readiness.md](12-production-readiness.md) — Windows does not have a direct
  `chmod`-equivalent single syscall from Rust's std without an extra crate, and adding one was
  judged out of scope for the MVP's dependency budget; the practical exposure is limited since
  `%APPDATA%` is already user-scoped by default on all supported Windows versions).

## 5.5 Supply-Chain / Dependency Hardening

- Dependency set is deliberately small and reviewed at add-time: every crate added via
  `cargo add` in this session is a widely used, actively maintained crate (RustCrypto workspace
  crates, `clap`, `serde`, `uuid`, `chrono`, etc.) — see [01-research-and-discovery.md §1.6](01-research-and-discovery.md).
  crates for `vault-core` and `vault-cli` respectively.
- **`vault-core` has zero networking dependencies** — grep-verified (`cargo tree`) and enforced
  going forward by the CI dependency check in [10-devsecops-cicd.md](10-devsecops-cicd.md) /
  `.github/workflows/ci.yml`.
- `cargo clippy --workspace --all-targets -- -D warnings` passes clean (zero warnings) as of
  this report.
- `cargo audit` (RustSec Advisory Database) and `cargo deny` (license + duplicate-version +
  advisory policy) were run in this session and are wired into CI. Both **found real issues on
  first run** (an unmaintained serialization dependency, an unpinned internal path dependency,
  and an unreviewed-but-legitimate license), all fixed within this session — full detail in
  [08-vapt-report.md §8.3](08-vapt-report.md). Final state: both tools report clean.

## 5.6 Error Handling

- `VaultError` ([error.rs](../crates/vault-core/src/error.rs)) `Display` messages are
  deliberately low-information; the `#[source]` chain (accessible via
  `std::error::Error::source`) still carries the real cause for `--debug`/structured logging,
  so nothing is lost for legitimate diagnosis — it's just not shown by default.
- `CliError` ([cli_error.rs](../crates/vault-cli/src/cli_error.rs)) maps every error to one of
  the four documented exit codes (0/1/3/4) so scripted callers can branch on outcome without
  parsing text.

## 5.7 Attack-Surface Reduction

- No background daemon, no listening socket, no IPC surface in the default (one-shot command)
  mode. `shell` mode is the only long-lived process, and it is opt-in and documented as a
  distinct trust boundary with its own mitigation (auto-lock).
- `panic = "abort"` in the release profile ([Cargo.toml](../Cargo.toml)) avoids unwind-based
  information leakage through panic payloads propagating across FFI/thread boundaries and
  produces smaller, simpler binaries.
- `strip = true` in the release profile removes debug symbols from shipped binaries, reducing
  the information available to an attacker who obtains the binary (though not a substitute for
  not having debug info in the first place during development).

## 5.8 Explicitly Deferred Hardening (tracked, not silently dropped)

| Item | Reason deferred | Tracking |
|---|---|---|
| Hash-chained/tamper-evident audit log | MVP scope; current log is append-only by convention + file permissions, not cryptographically chained (threat model T3) | [12-production-readiness.md](12-production-readiness.md) roadmap |
| Windows explicit ACL tightening beyond default user-profile scoping | Requires an extra crate (`windows-acl` or raw `windows-sys` ACL calls) not yet justified by risk given `%APPDATA%` is already user-scoped | [12-production-readiness.md](12-production-readiness.md) roadmap |
| OS keychain integration (e.g. Windows Credential Manager / macOS Keychain / Secret Service) as an optional local convenience unlock layer | Post-MVP feature, not a security regression to omit | [12-production-readiness.md](12-production-readiness.md) roadmap |
| Opt-in HIBP k-anonymity breach check | Would introduce the project's first network call; deliberately excluded from the default, offline-only threat model | [12-production-readiness.md](12-production-readiness.md) roadmap |
