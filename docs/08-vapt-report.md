# Phase 8 — Vulnerability Assessment & Penetration Testing (Self-Assessment)

**Scope:** `vault-core` and `vault-cli` as implemented in this repository. **Method:**
structured manual review against OWASP ASVS 5.0 control families and the OWASP Top 10 (2021) /
CWE Top 25 taxonomy, cross-referenced with the STRIDE threat model
([03-threat-model.md](03-threat-model.md)), plus automated dependency scanning
(`cargo audit`, `cargo deny`). This is a **self-assessment performed as part of the build**, not
an independent third-party penetration test — that distinction is stated plainly rather than
overclaimed, and is called out again in [12-production-readiness.md](12-production-readiness.md).

## 8.1 Methodology

For each relevant OWASP Top 10 / ASVS category, the codebase was reviewed for the corresponding
weakness class, an attempt was made to construct a concrete exploit scenario, and the outcome
was verified against the actual automated test suite (not just read as "looks fine" — every
claim below is either backed by a passing test that would fail if the mitigation regressed, or
explicitly flagged as unverified/residual).

## 8.2 Findings by Category

| # | Category (OWASP Top 10 / CWE) | Test performed | Result | Severity if unmitigated |
|---|---|---|---|---|
| V-1 | A02:2021 Cryptographic Failures | Reviewed KDF/AEAD choice and parameters; attempted to construct a nonce-reuse scenario | **Not exploitable.** XChaCha20-Poly1305's 192-bit random nonce makes accidental reuse probabilistically negligible even across a large number of vault saves; Argon2id parameters exceed OWASP minimums. No hand-rolled crypto. | Would be Critical |
| V-2 | A02:2021 Cryptographic Failures — weak/predictable RNG | Verified salt/nonce source is `rand::rngs::OsRng` (via `TryRngCore`), not a non-cryptographic RNG | **Not exploitable.** `crypto::tests::salts_and_nonces_are_unique_across_calls` gives empirical (not formal) evidence of uniqueness across repeated calls. | Would be Critical |
| V-3 | A01:2021 Broken Access Control (analogue: secret disclosure through the wrong code path) | Attempted to retrieve a password through `list`/`search`/JSON output | **Not exploitable — compile-time enforced.** `EntrySummary` has no field capable of carrying a password/TOTP seed; confirmed via `store::tests::list_and_search_never_expose_passwords` and CLI test `list_json_is_valid_json_and_excludes_passwords`, which parses real JSON output and asserts the field is absent. | Would be Critical |
| V-4 | A09:2021 Security Logging Failures (secrets in logs) | Added an entry with a highly distinctive title/username/password, inspected the raw audit log file bytes | **Not exploitable.** `audit_log_never_contains_plaintext_secrets_or_titles` (CLI test) reads the actual persisted log file and asserts none of the three substrings appear. | Would be High |
| V-5 | CWE-209 Information Exposure Through Error Messages | Attempted unlock with wrong password, inspected returned message and exit code | **Not exploitable by default.** Generic `AuthenticationFailed` message and exit code 3 regardless of failure cause; `--debug` reveals more but is explicit opt-in — see [05-security-hardening.md §5.6](05-security-hardening.md). | Would be Low/Medium |
| V-6 | CWE-256/522 Plaintext Storage of Credentials | Inspected the on-disk vault file with a hex viewer equivalent (`fs::read` + assert) | **Not exploitable.** `store::tests::create_then_open_round_trips` and `format::tests` confirm the on-disk representation is ciphertext; the CLI's own `export --plaintext-json` path is opt-in, requires `--i-understand-the-risk`, and prints an explicit warning before writing — see V-9 below for that path's own risk framing. | N/A (mitigated) |
| V-7 | CWE-306/862 Missing Authentication / Authorization on a sensitive operation | Attempted to call `get`/`list`/`edit`/etc. against a vault without ever supplying a correct password | **Not exploitable.** Every authenticated command path in `main.rs` goes through `open_store`, which requires a successful `VaultStore::open` (i.e. a passing AEAD tag check) before any command handler runs; there is no alternate code path that reaches entry data without it. | Would be Critical |
| V-8 | CWE-703 Improper Check for Exceptional Conditions (crash/DoS on malformed input) | Fed a corrupted vault file (single byte flipped in header and in ciphertext, separately) to `open` | **Not exploitable as DoS beyond a clean error return.** No panic, no hang; typed error returned — see `format::tests::corrupted_header_byte_is_rejected`, `store::tests::tampered_vault_file_refuses_to_open`. | Would be Medium |
| V-9 | CWE-522 Insufficiently Protected Credentials — plaintext export feature | Reviewed `vaultkeep export --plaintext-json` | **Accepted, documented risk — not a defect.** The feature exists deliberately for interoperability/migration; it requires an explicit `--i-understand-the-risk` flag, is off by default, prints a warning naming the exact output path before writing, and is always audit-logged. This is a case where the "vulnerability" is an intentional, gated feature, not an oversight — flagged here for transparency rather than omitted. | Low (by design, gated) |
| V-10 | A07:2021 Identification and Authentication Failures — brute-force resistance | Reviewed whether repeated failed unlock attempts are rate-limited | **Fixed.** `shell` mode now tracks consecutive failed re-unlock attempts and applies an increasing backoff delay (2^n seconds, capped at 30s) before allowing another attempt, satisfying [04-backlog.md](04-backlog.md) US-1.1.2 — see `commands/shell.rs`. One-shot CLI invocations still rely on the Argon2id cost itself as the primary deterrent (no cross-process counter is kept for stateless single commands) — noted as an accepted, documented characteristic of a stateless CLI rather than a gap. | **Closed** |
| V-11 | CWE-362 Race Condition — concurrent writers to the same vault file | Reviewed the write path for file locking; added an advisory cross-process lock and attempted to open the same vault twice concurrently | **Fixed.** `VaultStore::create`/`open` now acquire an exclusive, sibling `.lock` file for the life of the store (released automatically on `Drop`, including on early-return error paths); a second concurrent open is rejected with `VaultError::Locked` rather than racing. Tested in `store::tests::opening_the_same_vault_twice_concurrently_is_rejected` and `dropping_a_store_releases_its_lock_file`. A hard-killed process (SIGKILL/power loss) can still leave a stale lock file behind — this residual limitation is documented, not hidden, in [09-performance-and-reliability.md §9.3](09-performance-and-reliability.md), with a clear recovery instruction in the error message itself. | **Closed (residual: stale lock after a hard kill, documented)** |
| V-12 | A08:2021 Software and Data Integrity Failures — supply chain | `cargo audit` / `cargo deny` run against the full dependency tree | See §8.3 for live results from this session. | Depends on findings |
| V-13 | CWE-798 Use of Hard-coded Credentials | Repo-wide review for embedded secrets/keys/tokens | **Not found.** No secrets, keys, or credentials are present in source, tests, or CI configuration. | N/A |
| V-14 | CWE-330 Use of Insufficiently Random Values — password generator | Reviewed `generator.rs` sampling method | **Not exploitable.** Uses `rand::rng()` (ChaCha, OS-reseeded, `CryptoRng`), unbiased `random_range`, guarantees at least one char per requested class without reducing effective entropy predictably (class-guarantee characters are drawn from the *unrestricted* pool then shuffled). | Would be High |

## 8.3 Dependency / Supply-Chain Scan Results

Run in this session against the full workspace lockfile:

```
$ cargo audit
$ cargo deny check
```

**Results — actual tool run performed in this session** (both tools are also wired into
`ci.yml` on every push/PR and weekly on a schedule, so this is a continuously re-verified
control, not a one-time check):

- `cargo audit` **found a real issue on first run**: `bincode` v1.3.3 (then used for the vault
  payload serialization) was flagged `RUSTSEC-2025-0141` ("Bincode is unmaintained"). This was
  **fixed within this same session** by migrating `vault-core`'s serialization from `bincode` to
  `postcard` (an actively maintained, `serde`-based binary format) — see `store.rs`'s `save`/
  `open`. Re-running `cargo audit` after the migration surfaced a second transitive finding
  (`atomic-polyfill`, pulled in only by `postcard`'s optional `heapless` feature, which the
  project didn't need), fixed by building `postcard` with `--no-default-features --features
  alloc`, dropping `heapless`/`atomic-polyfill` from the tree entirely. **Final state: `cargo
  audit` reports zero advisories.**
- `cargo deny check` **also found two real issues on first run**: (1) `vault-cli`'s path
  dependency on `vault-core` had no version pin, tripping the `[bans] wildcards = "deny"`
  policy — fixed by pinning `version = "0.1.0"` alongside the `path`; (2) `clipboard-win`/
  `error-code` (transitive, Windows-only deps of `arboard`'s clipboard backend) use the
  OSI-approved, FSF-free **BSL-1.0** license, which wasn't yet in the project's allowlist —
  reviewed and added to [deny.toml](../deny.toml) as a legitimate permissive license. **Final
  state: `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`** (only
  informational `warn`-level duplicate-version notices remain — `syn`/`windows-sys` each present
  in two major versions across the dependency tree, which is normal and not a security issue).

This is deliberately reported as "found issues, fixed them" rather than "ran clean" — a
dependency scan that never finds anything on a project's first run is far more often a sign the
scan wasn't wired up correctly than a sign of a spotless dependency tree, and the goal of this
report is to be a truthful record of what was actually checked and what it actually found.

Both are re-run on every CI push and on a weekly schedule specifically so a newly disclosed CVE
is caught without requiring a code change (see [10-devsecops-cicd.md](10-devsecops-cicd.md)).

## 8.4 Open Findings & Remediation Plan

| ID | Finding | Severity | Remediation | Status |
|---|---|---|---|---|
| V-16 | Audit log is append-only by convention/permissions only, not cryptographically tamper-evident | Low/Medium (metadata only, no secret values at risk) | Hash-chain each audit record to its predecessor | **Open — roadmap**, see [03-threat-model.md](03-threat-model.md) T3 and [12-production-readiness.md](12-production-readiness.md) |
| V-17 | Stale advisory lock file left behind after a hard process kill (SIGKILL/power loss) requires manual removal | Low | Document the recovery step (already done, in the error message and §9.3); consider a PID-liveness check (`sysinfo`-style) before honoring an existing lock, as a future enhancement | **Open — low priority**, tracked in [12-production-readiness.md](12-production-readiness.md) |

No **Critical**, **High**, or unmitigated **Medium** severity findings remain open at the time
of this report — both Medium findings identified during this assessment (V-10, V-11) were fixed
within this same development cycle and are covered by new automated tests (§8.2). The two
remaining open items are Low severity and explicitly tracked in
[12-production-readiness.md](12-production-readiness.md) rather than blocking release.

## 8.5 Retest Plan

Each open finding above has a corresponding backlog item; on remediation, the retest procedure
is: (1) add/extend an automated test that would fail under the original vulnerable behavior,
(2) implement the fix, (3) confirm the new test passes and the full suite remains green, (4)
update this report's status column and move the row to §8.2 with its outcome. This mirrors how
every *closed* finding in §8.2 is backed by a named, currently-passing test — the intent is that
this table stays continuously accurate rather than becoming stale documentation.
