//! `vaultkeep shell` — an interactive session that re-parses each typed line through the exact
//! same `Cli`/`Command` grammar as the top-level binary (see `dispatch_authenticated` in
//! main.rs), so shell mode can never drift from one-shot command behavior. Auto-locks after
//! idle timeout via `session::IdleSession` (docs/04-backlog.md US-3.2).

use crate::cli_error::CliResult;
use crate::prompt;
use crate::session::IdleSession;
use crate::{dispatch_authenticated, Cli};
use clap::Parser;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use vault_core::VaultStore;

fn read_line(prompt_str: &str) -> CliResult<Option<String>> {
    print!("{prompt_str}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    let n = std::io::stdin().read_line(&mut buf)?;
    if n == 0 {
        return Ok(None); // EOF (Ctrl+D / Ctrl+Z)
    }
    Ok(Some(buf.trim_end().to_string()))
}

fn print_help() {
    println!(
        "Commands: add, get, list, search, edit, remove, check, totp, passwd, export, import,\n\
         audit-log, lock, help, exit"
    );
}

pub fn run(vault_path: &Path, audit_path: &Path, keyfile: Option<&Path>) -> CliResult<()> {
    println!("Vaultkeep interactive shell. Type 'help' for commands, 'exit' to quit.");
    let password = prompt::prompt_password("Master password", false)?;
    let store = VaultStore::open(vault_path, &password, keyfile, audit_path)?;
    let idle_timeout = Duration::from_secs(store.settings().session_idle_timeout_seconds as u64);
    println!("Unlocked. Auto-locks after {}s of inactivity.", idle_timeout.as_secs());
    let session = IdleSession::new(store, idle_timeout);
    // Consecutive failed re-unlock attempts within this shell session (VAPT finding V-10,
    // docs/08-vapt-report.md). Reset on any successful unlock; drives an increasing backoff
    // delay so a script left attached to an idle-locked shell can't hammer the KDF.
    let mut failed_unlock_attempts: u32 = 0;

    loop {
        let line = match read_line("vaultkeep> ")? {
            Some(l) => l,
            None => {
                session.lock_now();
                println!("\nLocked and exiting (EOF).");
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line.to_ascii_lowercase().as_str() {
            "exit" | "quit" => {
                session.lock_now();
                println!("Locked and exiting.");
                break;
            }
            "lock" => {
                session.lock_now();
                println!("Locked.");
                continue;
            }
            "help" => {
                print_help();
                continue;
            }
            _ => {}
        }

        if session.is_locked() {
            if failed_unlock_attempts > 0 {
                let delay_secs = 2u64.saturating_pow(failed_unlock_attempts.min(5)).min(30);
                println!(
                    "{failed_unlock_attempts} failed unlock attempt(s) — waiting {delay_secs}s before allowing another try."
                );
                std::thread::sleep(Duration::from_secs(delay_secs));
            }
            println!("Session is locked (idle timeout). Re-enter the master password to continue.");
            match prompt::prompt_password("Master password", false) {
                Ok(pw) => match VaultStore::open(vault_path, &pw, keyfile, audit_path) {
                    Ok(store) => {
                        session.unlock_with(store);
                        failed_unlock_attempts = 0;
                        println!("Unlocked.");
                    }
                    Err(e) => {
                        failed_unlock_attempts += 1;
                        eprintln!("Error: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    eprintln!("Error: {e}");
                    continue;
                }
            }
        }

        let tokens = match shlex::split(line) {
            Some(t) => t,
            None => {
                eprintln!("Could not parse input (unbalanced quotes?).");
                continue;
            }
        };
        let argv = std::iter::once("vaultkeep".to_string()).chain(tokens);
        let cli = match Cli::try_parse_from(argv) {
            Ok(c) => c,
            Err(e) => {
                println!("{e}");
                continue;
            }
        };

        match session.touch_and_use(|store| dispatch_authenticated(store, cli.command, false)) {
            Some(Ok(())) => {}
            Some(Err(e)) => eprintln!("Error: {e}"),
            None => println!("Session locked during command execution — try again."),
        }
    }
    Ok(())
}
