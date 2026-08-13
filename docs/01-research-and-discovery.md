# Phase 1 — Research & Discovery

**Project:** Vaultkeep — a local-first, cross-platform password/secret manager
**Date:** 2026-08-13

## 1.1 Problem Statement

Provide an individual or small team with a way to generate, store, retrieve, and manage
credentials and other secrets (passwords, API keys, recovery codes, notes) that is:

- Secure against offline theft of the vault file (laptop theft, backup leak, cloud-sync leak).
- Secure against local process/memory inspection to the extent an OS allows.
- Usable from a terminal on Windows, Linux, and macOS with no server dependency.
- Auditable, testable, and maintainable by a small team without a dedicated security engineer.

## 1.2 Scope Decision (recorded)

Three architecture options were evaluated with the project owner: (a) local-only vault,
(b) full self-hosted client-server vault (Bitwarden/Vaultwarden-style), (c) local-first now
with sync as a future roadmap item. **Decision: (a) local-only vault**, CLI-first, with a GUI
and sync explicitly deferred to the roadmap (see [12-production-readiness.md](12-production-readiness.md)).
This removes an entire class of network/API/multi-tenant attack surface from the MVP and lets
the project reach genuine production quality within scope, rather than a shallow implementation
of a much larger system.

Rationale for **Rust** as the implementation language: memory safety without a GC (predictable
zeroization of secret memory), a mature, independently-reviewed cryptography ecosystem
(RustCrypto workspace, `argon2`, `chacha20poly1305`), single statically-linked cross-platform
binaries, and a strong static-analysis/lint/SCA toolchain (`clippy`, `cargo-audit`, `cargo-deny`)
suited to a security-critical product.

## 1.3 Authoritative Standards Consulted

| Area | Standard / Source | Applicability |
|---|---|---|
| Memorized secrets, authenticator lifecycle | **NIST SP 800-63B** (SP 800-63-4, superseded Rev. 3 as of Aug 1, 2025) | Master-password policy: ≥8 char minimum, allow ≥64 chars, no forced complexity/rotation, check against breach corpora, resist offline attacks via salted KDF. |
| Key derivation function selection & parameters | **RFC 9106** (Argon2), **OWASP Password Storage Cheat Sheet** | Argon2id chosen over PBKDF2/bcrypt/scrypt. OWASP minimum: m=19 MiB, t=2, p=1 for server login use; a **local single-user vault KDF** is tuned much stronger (memory ≥ 256 MiB where feasible, one-shot cost is not amortized across millions of logins) — see [02-architecture.md §Security Architecture](02-architecture.md). |
| Authenticated encryption at rest | **NIST SP 800-38D** (AES-GCM), **RFC 8439** (ChaCha20-Poly1305) | XChaCha20-Poly1305 selected for the vault AEAD layer (extended 192-bit nonce removes nonce-collision risk under random generation; constant-time, no hardware-AES dependency, well-audited `chacha20poly1305` crate). |
| Secure application design checklist | **OWASP ASVS 5.0** (Application Security Verification Standard) | Used as the control checklist for Phases 5–8 (crypto, session/auto-lock, error handling, input validation). Mapped in [08-compliance-mapping.md](08-compliance-mapping.md). |
| Secure coding weaknesses taxonomy | **OWASP Top 10 (2021)**, **CWE Top 25** | Used during VAPT self-assessment ([07-vapt-report.md](07-vapt-report.md)) as the finding taxonomy. |
| CIS hardening baselines | **CIS Benchmarks** (for the OS the binary runs on), **CIS Controls v8** | Applied to file permissions, dependency hygiene, and the CI/CD runner configuration — see [05-security-hardening.md](05-security-hardening.md). |
| Time-based one-time passwords | **RFC 6238** (TOTP), **RFC 4226** (HOTP) | Vault can store TOTP seeds and generate codes for stored accounts (a common “secret manager” feature, distinct from securing the manager’s own auth). |
| ISMS / risk-management framing | **ISO/IEC 27001:2022** Annex A control themes | Used loosely to structure the risk register in [08-compliance-mapping.md](08-compliance-mapping.md) — full ISMS certification is out of scope for a single OSS-style tool but the control *language* is reused so the mapping is auditable. |
| Secrets-in-source hygiene | **OWASP Secrets Management Cheat Sheet** | Applied to the project's own repo/CI, not just the product: no secrets committed, `cargo-audit`/`gitleaks`-class scanning in CI. |
| CVE / dependency risk | **NVD / RustSec Advisory Database** via `cargo-audit` | Continuous SCA scanning of the dependency tree (Phase 10). |

## 1.4 Competitive / Reference Architecture Review

| Product | Model | Notable design choices reused | Deliberately not copied |
|---|---|---|---|
| **KeePass / KeePassXC** | Local encrypted DB file, AES-256/ChaCha20 + Argon2 KDF, offline-first | Single-file vault, strong KDF-tunable-cost pattern, plugin-free minimal core | Legacy KDBX2 formats, XML-based internal format (we use a versioned binary/CBOR-like envelope) |
| **`pass` (Unix password store)** | GPG-encrypted files in a directory tree, git-friendly | Simplicity, scriptability, git-based backup story | Per-entry GPG (no single master-key UX); we keep one vault file for atomic backup/versioning |
| **Bitwarden CLI / Vaultwarden** | Client-server, org/team sharing, sync | CLI ergonomics (`unlock`, session env var pattern), structured JSON entry model | Server component, account system — explicitly deferred (see roadmap) |
| **1Password** | Proprietary format (OPVault/1PUX), local cache + cloud sync, Secret Key + master password (2-factor-at-rest) | Concept of a machine-local “protection layer” in addition to the master password — informed our optional keyfile feature | Proprietary binary format, cloud dependency |

## 1.5 Key Requirements Derived

**Functional**
- Create/open/lock/unlock a vault protected by a master password (+ optional keyfile as a second factor).
- CRUD for secret entries: title, username, password, URL, notes, custom fields, tags, TOTP seed.
- Cryptographically strong password generation with configurable policy.
- Local password-strength estimation and breach-exposure hinting (k-anonymity HIBP check is a documented, opt-in, network-touching roadmap item — **disabled by default** to preserve the offline-only threat model).
- Search/list/filter entries.
- Clipboard copy-with-auto-clear.
- Session auto-lock after inactivity.
- Encrypted backup/export and restore.
- Local, tamper-evident audit log of vault operations (not secret values).

**Non-functional**
- Cross-platform: Windows 10+, major Linux distros (glibc ≥2.31), macOS 12+.
- No network calls in the default code path (verifiable — enforced in CI, see [05-security-hardening.md](05-security-hardening.md)).
- Vault file format versioned and forward-compatible; corruption of one record must not lose the whole vault where avoidable.
- Startup < 200 ms typical; KDF unlock time tuned to ~500 ms–1 s on commodity hardware (a deliberate, user-tunable delay — the *point* of the KDF cost).
- Deterministic, reproducible builds; supply-chain-scanned dependency tree.

**Constraints**
- Single maintainer/small team — the design favors a small, well-reviewed dependency surface over building crypto primitives from scratch (never hand-roll crypto).
- No paid infrastructure required to run the MVP (no server, no cloud KMS) — all trust anchors are local (OS keychain integration is an optional enhancement, see roadmap).

**Key risks identified** (elaborated in [03-threat-model.md](03-threat-model.md))
1. Weak/reused master password is the single largest real-world risk — mitigated by KDF cost tuning + strength meter + breach-corpus check (opt-in) + no silent fallback to a weaker KDF.
2. Secrets lingering in process memory or swap — mitigated by `zeroize`, `mlock`-class memory locking where the OS supports it, and minimizing secret lifetime.
3. Vault file exposure via cloud-sync folders (Dropbox/OneDrive) — the vault is encryption-at-rest by design so this is an accepted/mitigated risk, documented explicitly rather than assumed away.
4. Clipboard/history leakage — mitigated by auto-clear and documented OS clipboard-manager caveats.
5. Supply-chain risk in dependencies — mitigated by a minimal, pinned, `cargo-audit`/`cargo-deny`-scanned dependency set.

## 1.6 Technology Stack Selected

| Layer | Choice | Justification |
|---|---|---|
| Language | Rust (stable channel) | Memory safety, no GC, strong crypto ecosystem |
| KDF | Argon2id (`argon2` crate, RustCrypto) | RFC 9106 winner, OWASP-recommended default |
| AEAD | XChaCha20-Poly1305 (`chacha20poly1305` crate) | 192-bit nonce eliminates random-nonce collision risk; constant-time in software |
| Serialization | `serde` + `postcard` for the encrypted payload | Compact, deterministic, no ambiguous parsing |
| Secret hygiene | `zeroize`, `secrecy` | Best-effort memory scrubbing on drop |
| CLI framework | `clap` (derive) | De facto standard, strong UX, shell-completion generation |
| TOTP | `totp-rs` (RFC 6238-compliant) or hand-verified minimal HMAC-SHA1/256/512 implementation | Standardized 2FA code generation for stored accounts |
| Testing | built-in `cargo test`, `proptest` for property tests, `assert_cmd`/`predicates` for CLI integration tests | Layered unit + integration testing |
| Lint/SAST | `clippy` (`-D warnings`), `cargo-audit`, `cargo-deny` | Static analysis + dependency vulnerability/licence scanning |
| CI/CD | GitHub Actions, matrix build on `windows-latest`/`ubuntu-latest`/`macos-latest` | Native cross-platform verification, not cross-compilation guesswork |

## 1.7 Sources

- NIST SP 800-63B / SP 800-63-4 (Digital Identity Guidelines) — https://pages.nist.gov/800-63-3/ , https://csrc.nist.gov/pubs/sp/800/63/b/upd2/final
- OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 9106 (Argon2) — https://www.rfc-editor.org/rfc/rfc9106
- RFC 8439 (ChaCha20-Poly1305) — https://www.rfc-editor.org/rfc/rfc8439
- NIST SP 800-38D (AES-GCM) — https://csrc.nist.gov/pubs/sp/800/38/d/final
- OWASP ASVS 5.0 — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10 (2021) — https://owasp.org/Top10/
- RFC 6238 (TOTP) / RFC 4226 (HOTP) — https://www.rfc-editor.org/rfc/rfc6238 , https://www.rfc-editor.org/rfc/rfc4226
- CIS Controls v8 / CIS Benchmarks — https://www.cisecurity.org/
- ISO/IEC 27001:2022 — control-theme reference only
- OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- RustSec Advisory Database — https://rustsec.org/
