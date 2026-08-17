# Vaultkeep

A local-first, cross-platform (Windows / Linux / macOS) password and secret manager, available
as both a security-critical Rust **CLI** and a desktop **GUI** (Tauri) that shares the exact
same vault engine. No server, no account, no network calls by default — your vault is a single
encrypted file that only you can open.

## Download

Prebuilt, checksummed binaries for Windows, Linux, and macOS — both the `vaultkeep` CLI and the
Vaultkeep GUI installer (MSI/NSIS on Windows, DMG on macOS, deb/rpm/AppImage on Linux) — are
published to **[GitHub Releases](../../releases)** by the CI pipeline
([.github/workflows/release.yml](.github/workflows/release.yml)) whenever a `vX.Y.Z` tag is
pushed. Each asset ships with a `.sha256` checksum file alongside it — verify before running:

```
sha256sum -c vaultkeep-<platform>.sha256
```

No release has been tagged yet in this repository — see
[12-production-readiness.md](docs/12-production-readiness.md) for what's needed before the first
tag, or build from source below in the meantime.

```
$ vaultkeep init
Master password: ********
Confirm Master password: ********
Vault created at C:\Users\you\AppData\Roaming\vaultkeep\vault.vkl

$ vaultkeep add github.com --username alice --generate
Added entry ac1a9506-5667-42b2-bad9-d03ed3826f33

$ vaultkeep get github.com
Copied to clipboard; clearing automatically in 20s.

$ vaultkeep list
ac1a9506 github.com                   alice                dev
```

## Why

Most "build a password manager" exercises stop at "AES-encrypt a JSON file." Vaultkeep instead
went through a full research → architecture → implementation → security-hardening → VAPT →
compliance-mapping → production-readiness pass, documented end-to-end in [`docs/`](docs/). See
[docs/12-production-readiness.md](docs/12-production-readiness.md) for the honest final verdict,
including what's genuinely done and what's explicitly deferred.

## Security model, in one paragraph

Your master password (≥8 characters, checked against a common-password list — NIST SP 800-63B)
is stretched through **Argon2id** (RFC 9106) into a 256-bit key, which encrypts your vault with
**XChaCha20-Poly1305** (RFC 8439). The header is authenticated as associated data, so any
tampering with either the header or the ciphertext is detected and the vault refuses to open —
it never silently falls back to a weaker mode. Secrets are wrapped in a redacted type that
zeroizes on drop and never appears in `Debug`/`Display`/logs/error messages. There is no network
code in the vault engine at all — verified by a CI check on every push, not just asserted. Full
detail: [docs/02-architecture.md](docs/02-architecture.md#25-security-architecture-summary--full-detail-in-05-security-hardeningmd),
[docs/03-threat-model.md](docs/03-threat-model.md).

## Install

Grab a release binary/installer from [GitHub Releases](../../releases) for your platform, or
build from source:

```
# CLI
cargo build --release -p vault-cli
# binary at target/release/vaultkeep(.exe)

# GUI (needs the Tauri CLI: cargo install tauri-cli --version "^2.0.0" --locked)
cd apps/vault-gui && cargo tauri build
# installer at target/release/bundle/**
```

Requires the Rust stable toolchain. On Windows, either the MSVC toolchain (Visual Studio Build
Tools, "Desktop development with C++" workload) or the GNU toolchain
(`rustup toolchain install stable-x86_64-pc-windows-gnu` + a MinGW-w64 `gcc` on `PATH`) works;
this repository was built and tested against the GNU toolchain. The GUI additionally needs a
system WebView (WebView2 — preinstalled on Windows 10 2004+/11; WebKitGTK dev packages on Linux;
Xcode command line tools on macOS) — see [docs/13-gui.md](docs/13-gui.md).

> **Note on paths with spaces:** building the GUI's Windows resource bundling
> (`tauri-winres`/`windres`, via the GNU toolchain) can fail if your checkout path contains
> spaces — a local MinGW quirk, not a code issue (CI checkout paths don't have this problem).
> Workaround: `set CARGO_TARGET_DIR=` to a space-free path before building, e.g.
> `$env:CARGO_TARGET_DIR = "C:\vk-target"` in PowerShell.

## Usage

Full command reference: [docs/cli-reference.md](docs/cli-reference.md). Quick tour:

```
vaultkeep init                                    # create a new vault
vaultkeep add <title> [--username U] [--generate]  # add an entry
vaultkeep get <title> [--show]                     # copy (or show) a field
vaultkeep list / search <query>                    # browse without ever printing secrets
vaultkeep edit <title> [--regenerate]              # update fields / rotate a password
vaultkeep remove <title>                           # delete an entry
vaultkeep generate --length 24                     # print standalone generated passwords
vaultkeep check --all                              # strength/reuse/staleness report
vaultkeep totp <title>                             # current TOTP code for a stored seed
vaultkeep passwd                                   # rotate the master password
vaultkeep export --output backup.vkl               # encrypted backup
vaultkeep import backup.vkl [--merge]               # restore/merge a backup
vaultkeep audit-log                                # local, metadata-only activity trail
vaultkeep shell                                    # interactive session, auto-locks when idle
```

Secrets are **never** accepted as CLI arguments (they'd land in shell history / `ps` output) —
always a hidden prompt, or `--stdin` for scripted/CI use.

The desktop GUI covers the same everyday workflow (create/unlock, add/edit/delete entries,
generate passwords, TOTP codes, strength report, activity log, change master password) with the
same auto-lock and clipboard-auto-clear behavior — see [docs/13-gui.md](docs/13-gui.md) for what
it does and doesn't cover yet relative to the CLI.

## Project structure

```
crates/
  vault-core/   # security-critical library: crypto, vault format, data model, no network deps
  vault-cli/    # the `vaultkeep` binary: CLI, clipboard, session/auto-lock, terminal I/O
apps/
  vault-gui/    # desktop GUI (Tauri 2), reuses vault-core unchanged — see docs/13-gui.md
docs/           # the full SDLC documentation set — see below
.github/workflows/  # CI (build/test/lint/audit/deny) and release pipelines (CLI + GUI installers)
deny.toml       # cargo-deny policy (licenses, bans, advisories, sources)
```

## Documentation set

| Phase | Document |
|---|---|
| 1. Research & Discovery | [docs/01-research-and-discovery.md](docs/01-research-and-discovery.md) |
| 2. Architecture (HLD/LLD/security/deployment) | [docs/02-architecture.md](docs/02-architecture.md) |
| 2. Threat Model (STRIDE) | [docs/03-threat-model.md](docs/03-threat-model.md) |
| — Data model / schema reference | [docs/data-model.md](docs/data-model.md) |
| — CLI / API reference | [docs/cli-reference.md](docs/cli-reference.md) |
| — Desktop GUI architecture | [docs/13-gui.md](docs/13-gui.md) |
| 3. Agile backlog (epics → stories → sprints) | [docs/04-backlog.md](docs/04-backlog.md) |
| 5/6. Security engineering & hardening | [docs/05-security-hardening.md](docs/05-security-hardening.md) |
| 8. VAPT self-assessment | [docs/08-vapt-report.md](docs/08-vapt-report.md) |
| 9. Performance, reliability & DR | [docs/09-performance-and-reliability.md](docs/09-performance-and-reliability.md) |
| 10. DevSecOps & CI/CD | [docs/10-devsecops-cicd.md](docs/10-devsecops-cicd.md) |
| 11. Compliance mapping & risk register | [docs/11-compliance-mapping.md](docs/11-compliance-mapping.md) |
| 12. Production readiness review | [docs/12-production-readiness.md](docs/12-production-readiness.md) |

## Testing

```
cargo test --workspace     # 75 tests: 58 vault-core unit + 4 vault-cli unit + 13 CLI integration
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo deny check
```

The GUI has no separate automated test suite (it's a thin command layer over the already-tested
`vault-core`); it was verified by building and actually launching it, screenshotting the
create-vault and unlock flows — see [docs/13-gui.md](docs/13-gui.md) and
[docs/12-production-readiness.md](docs/12-production-readiness.md).

## License

MIT — see [LICENSE](LICENSE).
