# Phase 2 (cont.) — Threat Model

**Method:** STRIDE per trust boundary, plus an attacker-capability matrix. Scope: the local-only
Vaultkeep CLI as defined in [02-architecture.md](02-architecture.md). Out of scope: any future
sync server (tracked separately when/if that roadmap item is built).

## 3.1 Assets

| Asset | Sensitivity |
|---|---|
| Master password | Critical — root of trust for everything |
| Derived vault key (in memory) | Critical |
| Vault file (entries: passwords, TOTP seeds, notes) | Critical |
| Keyfile (if used) | High — second factor |
| Audit log (entry UUIDs, timestamps, op types) | Low — metadata only, no secret values |
| Config file (KDF profile, timeouts) | Low |
| Clipboard contents (transient) | High while present |

## 3.2 Trust Boundaries

1. **User ↔ CLI process** (keyboard input, terminal echo)
2. **CLI process ↔ OS** (memory, swap, process listing, clipboard, filesystem, ACLs)
3. **CLI process ↔ Filesystem** (vault file, audit log, config, backups)
4. **Local machine ↔ external media/cloud-sync folder** (if the user places the vault file in a
   synced folder — outside the app's control, but explicitly modeled since it's common practice)

## 3.3 Attacker Capability Matrix

| Attacker | Capability |
|---|---|
| A1 — Remote, no local access | Can only reach Vaultkeep if the user is tricked into running malicious input/import files. No network service exists to attack directly. |
| A2 — Local unprivileged user on shared machine | Can read files they have permission to, inspect process list, potentially ptrace if same UID/misconfigured. |
| A3 — Attacker with stolen laptop/device (powered off) | Full filesystem access to the vault file at rest, no live process. |
| A4 — Attacker with stolen laptop (unlocked OS session, Vaultkeep running/shell mode) | Can interact with a live, possibly-unlocked session. |
| A5 — Malicious/compromised dependency (supply chain) | Code-execution-equivalent within the process if a dependency is compromised. |
| A6 — Shoulder-surfing / clipboard manager on same machine | Observes terminal output or long-lived clipboard managers that persist history. |

## 3.4 STRIDE Analysis

| # | Threat (STRIDE) | Scenario | Boundary | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T1 | **Spoofing** — fake vault file accepted as genuine | Attacker plants a crafted file at the expected vault path | 3 | AEAD tag verification fails closed; magic bytes + version check; no auto-repair of failed auth | Low |
| T2 | **Tampering** — bit-flip/edit of vault file or header | A3 modifies ciphertext or header fields (e.g., downgrade `kdf_t_cost`) | 3 | Header is AEAD-authenticated as AAD; ciphertext has a 128-bit Poly1305 tag; any modification → decrypt failure | Low |
| T3 | **Tampering** — audit log rewritten to hide activity | Local attacker edits the plaintext audit log | 3 | Audit log is append-only by convention with restrictive file permissions; **not** cryptographically tamper-evident in the MVP (see limitation L-1 in [12-production-readiness.md](12-production-readiness.md)) | **Medium** — accepted for MVP, roadmapped (hash-chained log) |
| T4 | **Repudiation** — user denies performing an action | N/A (single local user, no multi-user accountability requirement) | — | Out of scope for single-user local tool | N/A |
| T5 | **Information Disclosure** — vault contents read at rest | A3 copies the vault file offline and brute-forces it | 3 | Argon2id m=256 MiB/t=3/p=1 makes offline GPU/ASIC brute force costly; strength meter + breach check nudge strong master passwords | **Medium** — inherent to any password-protected-at-rest design; mitigated, not eliminated. Documented plainly rather than overclaimed. |
| T6 | **Information Disclosure** — secret leaks via process memory / core dump / swap | A2/A4 inspects process memory or a crash writes a core dump containing the key/plaintext | 2 | `zeroize`/`SecretBox` wrappers scrub memory on drop; `mlock`/`VirtualLock` where available to reduce swap-out; core dumps disabled for the process where the OS allows (`RLIMIT_CORE=0` on Unix); secret types never implement `Debug`/`Display` | **Medium** — OS-level guarantees are best-effort, not absolute (documented limitation) |
| T7 | **Information Disclosure** — secret leaks via shell history / process args | User passes `--password` as a CLI argument, visible in `ps`/shell history | 1/2 | CLI **refuses** a `--password` flag entirely for secret values; always uses hidden interactive prompt or a piped-stdin mode explicitly documented as sensitive-use-only | Low |
| T8 | **Information Disclosure** — clipboard leakage | Secret copied to clipboard lingers, is synced by a cloud clipboard manager, or read by another app | 2/6 | Auto-clear after configurable timeout (default 20s), hash-guarded so we don't clobber a newer clipboard value; documented caveat that OS/3rd-party clipboard managers with history are outside the app's control | **Medium** — inherent OS limitation, clearly documented, not hidden |
| T9 | **Information Disclosure** — verbose error messages leak internal state | Error message reveals *which* KDF/AEAD check failed, aiding attacks | 1 | Generic `AuthenticationFailed`/`CorruptVault` errors at the CLI boundary; detailed cause only behind explicit `--debug` | Low |
| T10 | **Information Disclosure** — logging captures secrets | A bug logs a full `Entry` via `Debug`/`tracing` | 2/3 | Secret-bearing types implement redacted `Debug`; a Phase 7 automated test asserts no secret substring ever appears in captured log output across the whole command surface | Low (test-enforced) |
| T11 | **Denial of Service** — vault becomes unusable | Corruption, crash mid-write, or forgotten master password | 3 | Atomic write-then-rename (crash never corrupts the last-good vault); documented "forgotten master password = unrecoverable" as an explicit, intentional design property (no backdoor) | Accepted by design (zero-knowledge tradeoff) |
| T12 | **Denial of Service** — resource-exhaustion via crafted import file | Malicious import file with huge/garbage data crashes or hangs the process | 3 | Import size limits, structured parsing with `serde` (no unsafe deserialization), fuzzing target in Phase 7/8 | Low |
| T13 | **Elevation of Privilege** — malicious dependency executes arbitrary code | A5 compromises a transitive crate | all | Minimal dependency set, `cargo-audit`/`cargo-deny` in CI on every PR and on a schedule, lockfile committed, no build scripts from untrusted sources reviewed ad hoc | **Medium** — inherent supply-chain risk for any software; actively monitored, not eliminated |
| T14 | **Elevation of Privilege** — shell-mode session hijacked | A4 uses an unlocked interactive session left unattended | 2 | Idle auto-lock (default 300s) zeroizes the session key; explicit `lock` command; documented recommendation to prefer one-shot commands over `shell` mode on shared machines | Medium → Low with auto-lock |

## 3.5 Explicitly Out of Scope for the MVP Threat Model

- Multi-user access control / RBAC (no accounts — single local user by design, see
  [01-research-and-discovery.md §1.2](01-research-and-discovery.md)).
- Network-facing attack surface (no listeners, no outbound calls in the default path).
- Physical hardware attacks below the OS (cold-boot RAM extraction, JTAG) — acknowledged as
  theoretically possible against *any* software-only design, not specifically mitigated.
- Nation-state-grade side-channel cryptanalysis of the underlying RustCrypto primitives — the
  project relies on the upstream crates' own security review rather than re-implementing crypto.

## 3.6 Design Responses Traceability

Every "Medium" residual risk above is either (a) an accepted, explicitly documented tradeoff of
a local-only zero-knowledge design, or (b) tracked as a concrete roadmap item in
[12-production-readiness.md](12-production-readiness.md) (hash-chained audit log, OS-keychain
integration for an additional local unlock convenience layer). None are silently ignored.
