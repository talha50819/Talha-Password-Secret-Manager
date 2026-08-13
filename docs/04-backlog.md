# Phase 3 — Agile Scrum Backlog

Delivery model: Epics → Features → User Stories → Tasks, in ~1-week sprints. MVP = Sprints 1–4
(Epics 1–4); everything after is incremental. This backlog is the plan-of-record this session's
implementation follows.

## Epic 1 — Secure Vault Core (MVP-critical)

**Feature 1.1: Vault creation & unlock**
- **US-1.1.1** As a user, I can initialize a new vault with a master password so my secrets have a root of trust.
  - AC: `vaultkeep init` prompts twice, rejects mismatched/empty input, creates a file at the resolved default path with mode `0600` on Unix, refuses to overwrite an existing vault without `--force`.
  - DoD: unit tests for salt/nonce uniqueness across repeated `init` calls; integration test for file permissions on Unix.
- **US-1.1.2** As a user, I can unlock an existing vault with my master password.
  - AC: correct password decrypts; incorrect password returns a generic auth error (exit code 3) without revealing which check failed; 5 sequential failed unlocks in `shell` mode trigger an increasing delay (basic local throttle).
- **US-1.1.3** As a user, I can bind a vault to a keyfile as a second factor.
  - AC: vault created with `--keyfile` cannot be opened with password alone; keyfile bytes never written to the vault file or logs.

**Feature 1.2: Encrypted storage engine**
- **US-1.2.1** As a maintainer, the vault is encrypted with Argon2id + XChaCha20-Poly1305 per the security architecture.
  - AC: header fields match [data-model.md](data-model.md); tampering with any header byte or ciphertext byte causes decryption to fail (property-tested).
- **US-1.2.2** As a user, writes are atomic so a crash never corrupts my vault.
  - AC: kill-mid-write test (temp file + rename) leaves either old or new vault intact, never a partial file at the real path.

## Epic 2 — Entry Management (MVP-critical)

**Feature 2.1: CRUD**
- **US-2.1.1** Add / **US-2.1.2** Get / **US-2.1.3** Edit / **US-2.1.4** Remove / **US-2.1.5** List / **US-2.1.6** Search entries — each with AC per [cli-reference.md](cli-reference.md).
  - DoD (all): `list`/`search` output never contains password/TOTP-seed fields (compile-time via `EntrySummary`); integration tests cover happy path + not-found + duplicate title.

**Feature 2.2: Password generation & strength**
- **US-2.2.1** Generate a strong password with a configurable policy.
  - AC: CSPRNG-backed (`rand::rngs::OsRng`), respects length/character-class flags, `avoid_ambiguous` excludes the documented confusable set.
- **US-2.2.2** Get a strength/reuse/age report for stored entries.
  - AC: flags entries under a configurable entropy threshold, flags password reused across ≥2 entries, flags entries unrotated for > configurable days.

## Epic 3 — Session, Clipboard & Audit (MVP-critical)

- **US-3.1** Copy a secret to clipboard with auto-clear (default 20s), hash-guarded so a newer manual copy isn't clobbered.
- **US-3.2** `vaultkeep shell` keeps a session unlocked in memory and auto-locks after idle timeout (default 300s).
- **US-3.3** Every state-changing/auth operation is recorded to a local append-only audit log containing no secret values (schema in [data-model.md](data-model.md)).

## Epic 4 — Backup, Restore & Master-Password Rotation (MVP-critical)

- **US-4.1** `export`/`import` encrypted backups.
- **US-4.2** `passwd` rekeys the vault (new salt, new nonce, re-derive, atomic replace) without losing entries.

## Epic 5 — TOTP Support (post-MVP, Sprint 5)

- **US-5.1** Store a TOTP seed on an entry and compute the current RFC 6238 code + remaining-seconds countdown.

## Epic 6 — Security Hardening & Supply Chain (cross-cutting, Sprints 1–6)

- **US-6.1** CI enforces `clippy -D warnings`, `cargo-audit`, `cargo-deny` on every push/PR.
- **US-6.2** No secret type ever derives `Debug`/`Display` in a way that prints its value — enforced by a dedicated test that scrapes all captured output.
- **US-6.3** OS-appropriate file permission hardening applied to vault, audit log, and config files.

## Epic 7 — QA, VAPT & Compliance Documentation (Sprints 6–7)

- **US-7.1** Automated unit + integration test suite, ≥80% line coverage on `vault-core`.
- **US-7.2** VAPT self-assessment executed and findings remediated or explicitly risk-accepted.
- **US-7.3** Compliance/control mapping published (NIST 800-63B, OWASP ASVS, CWE Top 25).

## Epic 8 — DevSecOps & Release Engineering (Sprints 7–8)

- **US-8.1** Cross-platform CI matrix build + release pipeline producing signed-checksum artifacts for Windows/Linux/macOS.

## Sprint Plan (MVP = Sprints 1–4)

| Sprint | Goal | Epics |
|---|---|---|
| 1 | Crypto core + file format + `init`/unlock | Epic 1 |
| 2 | Entry CRUD + generator + strength | Epic 2 |
| 3 | Clipboard, shell/auto-lock, audit log | Epic 3 |
| 4 | Backup/restore, rekey, MVP hardening pass, MVP test suite | Epic 4, part of Epic 6/7 |
| 5 | TOTP, deeper hardening, VAPT self-assessment | Epic 5, Epic 6, Epic 7 |
| 6 | CI/CD pipeline, compliance mapping, performance pass | Epic 8, Epic 7 |
| 7+ | Roadmap: GUI, OS keychain integration, sync server | (post-MVP, see [12-production-readiness.md](12-production-readiness.md)) |

## Definition of Done (applies to every story)

1. Code compiles with `clippy -D warnings` on all three target platforms in CI.
2. Unit and/or integration tests added and passing.
3. No secret value reachable through logs, `Debug` output, error messages, or `list`/`search`.
4. Public behavior matches [cli-reference.md](cli-reference.md) (doc updated in the same change if behavior changes).
5. Threat model ([03-threat-model.md](03-threat-model.md)) reviewed for new attack surface; updated if needed.
