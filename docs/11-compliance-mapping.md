# Phase 11 — Compliance & Control Mapping, Risk Register

## 11.1 Purpose & Scope

Vaultkeep is a local-only, single-user tool, not a regulated service — there is no PCI/HIPAA/
SOC2-style audit obligation inherent to the product itself. This section maps the
implementation against the *technical control* frameworks that are actually applicable
(NIST SP 800-63B, OWASP ASVS, CWE) so the security posture is verifiable against named,
authoritative criteria rather than asserted in the abstract, and provides a risk register in
the ISO/IEC 27001 Annex A control-theme style for structure and auditability.

## 11.2 NIST SP 800-63B (Digital Identity Guidelines) — Memorized Secrets

| Control | Requirement | Vaultkeep implementation | Status |
|---|---|---|---|
| 5.1.1.1 | Verifiers SHALL require memorized secrets ≥ 8 characters | `strength::validate_master_password` enforces an 8-character minimum on the master password, called from both `VaultStore::create` and `rekey` — a single source of truth so neither `init` nor `passwd` can bypass it (tested: `create_rejects_a_master_password_below_the_nist_minimum_length`, `rekey_rejects_a_weak_new_master_password`) | **Met** |
| 5.1.1.1 | Verifiers SHOULD permit memorized secrets ≥ 64 characters | No maximum length is enforced anywhere in the master password or entry password path | **Met** |
| 5.1.1.2 | No composition rules (mandatory uppercase/digit/symbol) SHOULD be imposed on user-chosen memorized secrets | Master password has no composition requirement; the *generator* (a different, opt-in feature for generating new passwords) does offer configurable character classes, which is not the same as imposing rules on a user-chosen password | **Met** |
| 5.1.1.2 | Verifiers SHALL compare against a list of commonly-used/compromised values and reject/warn | The same `validate_master_password` call rejects a master password matching the embedded common-password list at `init`/`passwd` time (hard rejection, not advisory-only) — tested: `create_rejects_a_common_master_password_even_if_long_enough`. **Stored entry passwords** get the separate, deliberately advisory (report-only) `vaultkeep check` treatment, since the vault must be able to hold a legacy weak password a site imposes — that distinction is intentional, not a gap (see R-2 below, closed) | **Met** |
| 5.1.1.2 | Memorized secrets SHALL be salted and hashed/stretched with a suitable one-way KDF resistant to offline attack | Argon2id, RFC 9106, tuned above the OWASP minimum | **Met** |
| 5.1.1.2 | No periodic mandatory rotation | No rotation is enforced or nagged for beyond the advisory "stale" flag in `check`, which is informational | **Met** (intentionally not enforced) |

## 11.3 OWASP ASVS 5.0 — Selected Applicable Controls

| ASVS Area | Control theme | Vaultkeep implementation | Status |
|---|---|---|---|
| V2 Authentication | Secrets never logged or exposed in error messages | `Secret` redacted `Debug`/`Display`; generic `AuthenticationFailed` message | **Met** |
| V3 Session Management | Session has an idle timeout and explicit termination | `shell` mode `IdleSession` auto-lock (default 300s) + `lock`/`exit` commands | **Met** |
| V6 Stored Cryptography | Approved, vetted cryptographic algorithms used for data at rest | Argon2id + XChaCha20-Poly1305 via RustCrypto crates | **Met** |
| V6 Stored Cryptography | Keys/secrets zeroized when no longer needed | `zeroize`/custom `Secret` `Drop` impls | **Met** |
| V7 Error Handling and Logging | Errors do not expose sensitive information by default | Low-information `Display`, detail gated behind `--debug` | **Met** |
| V7 Error Handling and Logging | Security-relevant events are logged | Local audit trail covering init/unlock/CRUD/export/import/rekey | **Met** |
| V8 Data Protection | Sensitive data is not included in exports without explicit user action | `export --plaintext-json` requires `--i-understand-the-risk` and prints a warning | **Met** |
| V9 Communications | No sensitive data sent over the network without explicit protection | N/A by design — zero network calls in the default path (verified in CI, [10-devsecops-cicd.md](10-devsecops-cicd.md)) | **Met (N/A)** |
| V14 Configuration | Dependencies are scanned for known vulnerabilities | `cargo audit` + `cargo deny` in CI, weekly schedule | **Met** |

## 11.4 CWE Top 25 — Applicable Weakness Classes Reviewed

Cross-referenced against the VAPT self-assessment ([08-vapt-report.md](08-vapt-report.md)):
CWE-209 (error message info exposure), CWE-256/522 (plaintext credential storage), CWE-306/862
(missing auth), CWE-330 (insufficiently random values), CWE-362 (race condition), CWE-703
(improper exception handling), CWE-798 (hardcoded credentials). See that report for the
per-item finding, evidence, and status.

## 11.5 Risk Register

Risk = Likelihood × Impact, both rated Low/Medium/High. ISO/IEC 27001 Annex A control-theme
column used purely for structure/cross-reference, not as a certification claim.

| ID | Risk | Likelihood | Impact | Rating | Related Annex A theme | Treatment |
|---|---|---|---|---|---|---|
| R-1 | User sets a very short/weak master password (no minimum length enforced at `init`) | Was Medium | High | Was **High** | A.5 (Access control) / A.8 (Asset — cryptography) | **Mitigated, closed**: `validate_master_password` enforces the NIST SP 800-63B 8-character minimum at both `init` and `passwd`, in `vault-core` (not just the CLI layer), so it can't be bypassed by any future caller of the library. |
| R-2 | Master password itself is never checked against the common-password blocklist (only stored entries are) | Was Medium | High | Was **High** | A.5 / A.8 | **Mitigated, closed**: the same validator hard-rejects (not just warns) a master password matching the common-password list at `init`/`passwd` — a deliberately stricter treatment than for stored entry passwords, justified because the master password protects everything else and has no legacy-site constraint forcing a weak choice. |
| R-3 | Stale advisory lock file after a hard process kill blocks legitimate reopening | Low | Low | **Low** | A.5 | **Accept + document**: clear recovery instruction is in the error message itself (V-17, [08-vapt-report.md](08-vapt-report.md)). |
| R-4 | Audit log is not cryptographically tamper-evident | Low | Low (metadata only) | **Low** | A.8 (Logging) | **Accept, roadmap**: hash-chaining tracked for a future release (T3, [03-threat-model.md](03-threat-model.md)). |
| R-5 | Cloud-sync folder placement of the vault file could expose it to a third-party's own compromise, even though it's encrypted | Low (opt-in user choice) | Medium | **Low/Medium** | A.5 | **Accept, document**: this is explicitly discussed as an accepted-by-design tradeoff in [03-threat-model.md](03-threat-model.md) T5 rather than silently assumed away. |
| R-6 | Supply-chain compromise of a transitive dependency | Low | High | **Medium** | A.8 (Supply chain) | **Mitigate + monitor**: `cargo audit`/`cargo deny` on every push and weekly schedule; minimal, reviewed dependency set (see [08-vapt-report.md §8.3](08-vapt-report.md) for the current scan result). |
| R-7 | Concurrent-process race on the vault file | Was Medium | High | Was **Medium** | A.8 | **Mitigated**: advisory cross-process lock implemented and tested (V-11, closed). Residual risk is R-3. |
| R-8 | Forgotten master password is permanently unrecoverable | High (eventually, for some users) | High (data loss) | **High**, but **intentional** | A.5 | **Accept by design**: zero-knowledge architecture has no backdoor; mitigated only via user education (clear documentation, backup-export guidance) — see [09-performance-and-reliability.md §9.6](09-performance-and-reliability.md). |

## 11.6 Residual Risk Summary

After treatment, the residual risk profile is dominated by **user behavior** within the bounds
the tool now enforces (choosing a memorable-but-not-trivially-guessable master password above
the 8-character/non-common floor, forgetting it, or not managing backups) rather than
implementation defects — the expected and appropriate residual-risk shape for a correctly
implemented zero-knowledge local vault. The two **High**-rated implementation gaps identified
in this pass (R-1, R-2 — master password strength enforcement) were closed within the same
development cycle rather than merely scheduled, and are covered by dedicated regression tests
so they cannot silently regress (`store::tests::create_rejects_a_master_password_below_the_nist_minimum_length`,
`create_rejects_a_common_master_password_even_if_long_enough`, `rekey_rejects_a_weak_new_master_password`).
