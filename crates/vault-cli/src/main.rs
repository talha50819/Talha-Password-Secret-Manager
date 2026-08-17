mod cli_error;
mod clipboard;
mod commands;
mod config;
mod prompt;
mod session;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use cli_error::{CliError, CliResult};
use commands::entries::FieldArg;
use std::path::PathBuf;
use vault_core::VaultStore;

/// Vaultkeep — a local-first, cross-platform password and secret manager.
/// See docs/cli-reference.md for the full command reference.
#[derive(Parser)]
#[command(name = "vaultkeep", version, about, long_about = None)]
pub struct Cli {
    /// Override the default vault file location.
    #[arg(long, global = true)]
    pub vault: Option<PathBuf>,

    /// Path to a keyfile bound to the vault (required if the vault was created with one).
    #[arg(long, global = true)]
    pub keyfile: Option<PathBuf>,

    /// Emit machine-readable JSON where supported.
    #[arg(long, global = true)]
    pub json: bool,

    /// Print full internal error detail (never enabled by default — see docs/03-threat-model.md T9).
    #[arg(long, global = true)]
    pub debug: bool,

    /// Read secrets from a single line of stdin instead of an interactive hidden prompt.
    /// Scripted/CI use only — see docs/cli-reference.md and docs/03-threat-model.md T7.
    #[arg(long, global = true)]
    pub stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new vault.
    Init {
        #[arg(long, default_value = "default")]
        kdf_profile: String,
        /// Generate a strong random master password instead of typing one (shown once, never
        /// stored — save it before continuing).
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 24)]
        length: u16,
    },
    /// Add a new entry.
    Add {
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: u16,
    },
    /// Retrieve a field from an entry (default: copy password to clipboard).
    Get {
        title: String,
        #[arg(long, value_enum, default_value = "password")]
        field: FieldArg,
        #[arg(long)]
        show: bool,
    },
    /// List entries (never prints passwords).
    List {
        #[arg(long)]
        tag: Option<String>,
    },
    /// Search entries by title/username/url/notes/tags.
    Search { query: String },
    /// Update fields on an existing entry. Pass an empty string to clear a field.
    Edit {
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        regenerate: bool,
        #[arg(long, default_value_t = 20)]
        length: u16,
    },
    /// Delete an entry.
    Remove {
        title: String,
        #[arg(long)]
        force: bool,
    },
    /// Print one or more generated passwords (does not touch the vault).
    Generate {
        #[arg(long, default_value_t = 20)]
        length: u16,
        #[arg(long)]
        no_upper: bool,
        #[arg(long)]
        no_lower: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        allow_ambiguous: bool,
        #[arg(long, default_value_t = 1)]
        count: usize,
    },
    /// Strength/reuse/age report for one or all entries.
    Check {
        title: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 365)]
        stale_after_days: i64,
    },
    /// Print the current TOTP code for an entry.
    Totp { title: String },
    /// Change the master password (rekeys the vault).
    Passwd {
        /// Generate a strong random master password instead of typing one (shown once, never
        /// stored — save it before continuing).
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 24)]
        length: u16,
    },
    /// Export an encrypted backup (or, opt-in, a plaintext JSON dump).
    Export {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        plaintext_json: bool,
        #[arg(long)]
        i_understand_the_risk: bool,
    },
    /// Import/restore entries from a backup file.
    Import {
        path: PathBuf,
        #[arg(long)]
        merge: bool,
    },
    /// View the local audit trail (metadata only — never secret values).
    AuditLog {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Interactive session that auto-locks after inactivity.
    Shell,
    /// Generate shell completion scripts.
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn init_logging(json: bool) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let subscriber = fmt().with_env_filter(filter).with_writer(std::io::stderr);
    if json {
        let _ = subscriber.json().try_init();
    } else {
        let _ = subscriber.try_init();
    }
}

/// Dispatch a command that requires an already-unlocked `VaultStore`. Shared between the
/// top-level `main` and `commands::shell`, which re-parses each typed line through the same
/// `Command` grammar so the two entry points can never drift apart (docs/04-backlog.md DoD #4).
pub(crate) fn dispatch_authenticated(store: &mut VaultStore, command: Command, use_stdin: bool) -> CliResult<()> {
    let clipboard_clear_secs = store.settings().clipboard_clear_seconds;
    match command {
        Command::Add { title, username, url, notes, tags, generate, length } => {
            commands::entries::add(store, title, username, url, notes, tags, generate, length, use_stdin)
        }
        Command::Get { title, field, show } => commands::entries::get(store, &title, field, show, clipboard_clear_secs),
        Command::List { tag } => commands::entries::list(store, tag.as_deref(), false),
        Command::Search { query } => commands::entries::search(store, &query, false),
        Command::Edit { title, username, url, notes, tags, regenerate, length } => {
            commands::entries::edit(store, &title, username, url, notes, tags, regenerate, length)
        }
        Command::Remove { title, force } => commands::entries::remove(store, &title, force),
        Command::Check { title, all, stale_after_days } => {
            commands::check::run(store, title.as_deref(), all, false, stale_after_days)
        }
        Command::Totp { title } => commands::totp_cmd::run(store, &title),
        Command::Passwd { generate, length } => commands::passwd::run(store, None, generate, length, use_stdin),
        Command::Export { output, plaintext_json, i_understand_the_risk } => {
            commands::backup::export(store, &output, plaintext_json, i_understand_the_risk)
        }
        Command::Import { path, merge } => commands::backup::import(store, &path, merge, use_stdin),
        Command::AuditLog { tail } => commands::audit_log::run(store, tail, false),
        Command::Init { .. } | Command::Shell | Command::Generate { .. } | Command::Completions { .. } => {
            Err(CliError::from(vault_core::VaultError::InvalidInput(
                "this command is not valid inside an already-open session".into(),
            )))
        }
    }
}

fn run() -> CliResult<()> {
    let cli = Cli::parse();
    init_logging(cli.json);
    let debug = cli.debug;

    let vault_path = config::resolve_vault_path(cli.vault.clone());
    let audit_path = config::audit_log_path_for(&vault_path);

    let result = match cli.command {
        Command::Init { kdf_profile, generate, length } => commands::init::run(
            &vault_path,
            &audit_path,
            cli.keyfile.as_deref(),
            &kdf_profile,
            generate,
            length,
            cli.stdin,
        ),
        Command::Generate { length, no_upper, no_lower, no_digits, no_symbols, allow_ambiguous, count } => {
            commands::generate::run(length, no_upper, no_lower, no_digits, no_symbols, allow_ambiguous, count)
        }
        Command::Completions { shell } => commands::completions::run(shell),
        Command::Shell => commands::shell::run(&vault_path, &audit_path, cli.keyfile.as_deref()),

        // JSON-capable read commands need the flag threaded through before the generic
        // dispatcher (which always renders human-readable output) takes over.
        Command::List { ref tag } if cli.json => {
            let store = open_store(&vault_path, &audit_path, cli.keyfile.as_deref(), cli.stdin)?;
            commands::entries::list(&store, tag.as_deref(), true)
        }
        Command::Search { ref query } if cli.json => {
            let store = open_store(&vault_path, &audit_path, cli.keyfile.as_deref(), cli.stdin)?;
            commands::entries::search(&store, query, true)
        }
        Command::Check { ref title, all, stale_after_days } if cli.json => {
            let store = open_store(&vault_path, &audit_path, cli.keyfile.as_deref(), cli.stdin)?;
            commands::check::run(&store, title.as_deref(), all, true, stale_after_days)
        }
        Command::AuditLog { tail } if cli.json => {
            let store = open_store(&vault_path, &audit_path, cli.keyfile.as_deref(), cli.stdin)?;
            commands::audit_log::run(&store, tail, true)
        }

        other => {
            let mut store = open_store(&vault_path, &audit_path, cli.keyfile.as_deref(), cli.stdin)?;
            dispatch_authenticated(&mut store, other, cli.stdin)
        }
    };

    // Detailed cause chain is only ever shown behind an explicit opt-in flag — the default
    // path always returns the single low-information message (docs/03-threat-model.md T9).
    if let Err(ref e) = result {
        if debug {
            print_debug_chain(e);
        }
    }
    result
}

fn print_debug_chain(e: &CliError) {
    eprintln!("--- debug: full error detail (--debug) ---");
    match e {
        CliError::Vault(v) => {
            eprintln!("{v:?}");
            let mut source = std::error::Error::source(v);
            while let Some(s) = source {
                eprintln!("caused by: {s}");
                source = s.source();
            }
        }
        CliError::Other(o) => eprintln!("{o:?}"),
    }
}

fn open_store(
    vault_path: &std::path::Path,
    audit_path: &std::path::Path,
    keyfile: Option<&std::path::Path>,
    use_stdin: bool,
) -> CliResult<VaultStore> {
    let password = prompt::prompt_password("Master password", use_stdin)?;
    Ok(VaultStore::open(vault_path, &password, keyfile, audit_path)?)
}

fn main() {
    match run() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(e.exit_code());
        }
    }
}
