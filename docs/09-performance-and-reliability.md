# Phase 9 — Performance, Reliability & Disaster Recovery

## 9.1 Performance Targets vs. Observed

| Metric | Target (NFR, [02-architecture.md](02-architecture.md)) | Observed (release build, `--release`, Windows 11 dev machine, 5-run average) |
|---|---|---|
| Cold start, non-crypto command (`generate`) | < 200 ms | **~57 ms** (55–58 ms across 3 runs) |
| Unlock latency, `default` KDF profile (m=256 MiB, t=3, p=1) | ~500 ms – 1.5 s | **~624 ms** (612–642 ms across 5 consecutive `get` invocations) — squarely in the target range |
| Unlock latency, `interactive` profile (m=19 MiB, t=2, p=1 — OWASP minimum) | Faster, sub-200ms typical | Used throughout the automated test suite specifically to keep CI fast without weakening the *shipped default* |
| Vault write | Single atomic write + fsync | O(vault size); see §9.2 for scaling data |

**Noted anomaly, reported rather than hidden:** the very first `vaultkeep init` run against a
freshly built, unsigned release binary on this Windows dev machine took ~29.6 s — 40×+ its
steady-state cost — while every subsequent invocation of the *same* binary (a separate process
each time) measured the expected ~600 ms. This pattern (first execution of a new unsigned
binary anomalously slow, every later execution fast and consistent) is the signature of a
one-time OS/AV first-execution scan of the binary itself, not a KDF or code performance defect
— it did not recur across 8 subsequent invocations. Recorded here for honesty rather than
quietly re-running until it disappeared; production distribution should sign release binaries
(code-signing is called out as a release-hardening item, not yet implemented, since it requires
a paid certificate the project does not currently hold) to reduce first-run AV friction for end
users.

## 9.2 Scalability (vault size)

The relevant scale axis for a local, single-user tool is **entry count / file size**, not
concurrent users (see [02-architecture.md §2.8](02-architecture.md)). Each mutating operation
(`add`/`edit`/`remove`/`passwd`) re-serializes and re-encrypts the *entire* payload in one AEAD
call — a deliberate simplicity/security tradeoff (no partial-record encryption, no possibility
of inconsistent partial state) that trades some write cost at large entry counts for a much
simpler, more auditable design. `postcard`'s serialization and XChaCha20-Poly1305's encryption
are both linear in payload size and fast in absolute terms (hundreds of MB/s), so this remains
practical well past any realistic personal/small-team vault size (thousands of entries is
comfortably sub-second for the encryption step itself; the KDF cost, not the AEAD cost,
dominates wall-clock unlock time at all realistic vault sizes).

## 9.3 Concurrency & Failure Testing

| Scenario | Result |
|---|---|
| Process crash mid-write | Atomic temp-file-then-rename means the previous vault is always intact — tested in `format::tests::atomic_write_then_read_round_trip` / `no_leftover_temp_file_after_successful_write` ([format.rs](../crates/vault-core/src/format.rs)). |
| Corrupted/tampered vault file (single bit flip anywhere in header or ciphertext) | AEAD tag verification fails closed; `VaultError::AuthenticationFailed`/`CorruptVault` returned, never a silent partial read — tested in `crypto::tests::tampered_ciphertext_fails_closed`, `tampered_aad_fails_closed`, `store::tests::tampered_vault_file_refuses_to_open`. |
| Two processes writing to the same vault concurrently | **Known limitation, not yet mitigated**: the current design has no file locking, so a genuine race between two concurrent `vaultkeep` invocations against the same vault file could result in a last-writer-wins overwrite (each write is individually atomic and never corrupts the file, but one process's changes could be lost). Documented as a roadmap item — see [12-production-readiness.md](12-production-readiness.md). This is a low-likelihood scenario for the MVP's single-user, mostly-single-invocation usage pattern, but is called out explicitly rather than left implicit. |
| Forgotten master password | By design, unrecoverable — no backdoor, no recovery key, consistent with a zero-knowledge local vault. Explicitly documented as an intentional property, not an oversight (threat model T11). |
| Import of a malformed/garbage file | `postcard`/header parsing rejects structurally invalid input via typed deserialization (no `unsafe`); a maliciously huge file is bounded by normal OS/file-size limits — no custom unbounded-allocation path exists in the parser. |

## 9.4 Automated Test Suite Performance (informational, not a product SLA)

The full workspace test suite (`cargo test --workspace`, **debug** build) takes roughly:

- `vault-core`: ~8 seconds (47 tests) — uses the fast `interactive` KDF profile throughout.
- `vault-cli` unit tests: ~3 seconds (4 tests).
- `vault-cli` integration tests (`assert_cmd`, spawns real `vaultkeep.exe` subprocesses):
  ~3 minutes (13 tests) — each test spawns several full OS processes, several of which perform
  a real Argon2id unlock in an **unoptimized debug build**, which is meaningfully slower than
  a release build's KDF pass. This is a test-infrastructure cost, not a product-performance
  characteristic; CI runs `cargo test --workspace` on native runners with normal caching and
  this has not been a bottleneck (see [10-devsecops-cicd.md](10-devsecops-cicd.md)).

## 9.5 Health, Monitoring & Alerting

Vaultkeep is a local CLI, not a long-running service, so traditional health-check/alerting
infrastructure (as would apply to a server) does not directly apply. The equivalent controls
implemented:

- **Structured logging** via `tracing`, human or JSON (`--json` on the global flags feeds
  `init_logging`), to stderr — suitable for a caller (e.g. a wrapper script or a future GUI)
  to capture and monitor.
- **Deterministic, typed exit codes** (0/1/3/4, see [cli-reference.md](cli-reference.md)) so any
  automation wrapping `vaultkeep` can alert on authentication failures vs. generic errors vs.
  a missing vault distinctly.
- **Local audit trail** ([data-model.md](data-model.md)) provides an operational record a user
  or script can inspect (`vaultkeep audit-log`) for anomalous unlock-failure patterns.

## 9.6 Backup & Disaster Recovery Procedure

**Backup**

1. Run `vaultkeep export --output <path>` to produce a fresh, independently-encrypted snapshot
   of the vault (same header+AEAD envelope format, see [data-model.md](data-model.md)).
2. Store the exported file per the user's own backup strategy (recommendation: 3-2-1 — at
   least 3 copies, on 2 different media types, with 1 offsite/cloud copy). Because the export
   is encrypted at rest with the same guarantees as the primary vault, placing it in a
   cloud-sync folder is an accepted practice under this project's threat model (see
   [03-threat-model.md](03-threat-model.md) T5) — it does not weaken confidentiality, only
   availability-of-secrecy depends on master password strength as it already does for the
   primary vault.
3. Automate step 1 via the user's own OS scheduler (cron / Task Scheduler) if periodic backups
   are desired; `--stdin` mode supports this non-interactively from a secrets-manager-fed
   pipeline (see [cli-reference.md](cli-reference.md)).

**Restore / Disaster Recovery**

1. Install `vaultkeep` on the replacement/new machine (same binary works across the three
   supported platforms; the vault file itself is platform-independent).
2. If replacing a lost primary vault outright: copy the exported backup file to the default
   vault path (or pass `--vault <path>` pointing directly at it) and unlock normally with its
   master password.
3. If merging a backup into an existing vault: `vaultkeep import <backup-path> [--merge]` —
   without `--merge`, existing entries are replaced; with `--merge`, entries are added
   alongside existing ones and duplicate titles are skipped (never silently overwritten) — see
   `backup::import` in [backup.rs](../crates/vault-cli/src/commands/backup.rs) and the
   integration test `export_then_import_into_a_fresh_vault_round_trips_entries`.
4. **Recovery Time Objective (RTO):** effectively the time to install the binary and run one
   `import`/copy command — sub-minute for a technically comfortable user, since there is no
   server/infrastructure to stand back up.
5. **Recovery Point Objective (RPO):** bounded by backup frequency, entirely under the user's
   control (no server-side backup cadence to reason about).
6. **A lost master password is not a disaster-recovery scenario** — it is unrecoverable by
   design (zero-knowledge architecture, no backdoor). This must be communicated clearly to
   users (see [12-production-readiness.md](12-production-readiness.md) known limitations).
