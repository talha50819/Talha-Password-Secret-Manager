//! Interactive prompts. Secrets are **never** accepted as CLI arguments (threat model T7) —
//! they always come from a hidden interactive prompt, or, when `--stdin` is explicitly passed,
//! a single line read from stdin. `--stdin` is documented (docs/cli-reference.md) as a
//! sensitive-use mode intended for scripted/CI callers piping from a secret store — not for a
//! human to type a password where a terminal would echo or a shell history could capture it.

use crate::cli_error::CliResult;
use std::io::BufRead;
use vault_core::Secret;

fn read_stdin_line() -> CliResult<String> {
    let mut buf = String::new();
    std::io::stdin().lock().read_line(&mut buf)?;
    // Trim only the trailing line ending, not arbitrary whitespace a password might contain.
    while buf.ends_with('\n') || buf.ends_with('\r') {
        buf.pop();
    }
    Ok(buf)
}

pub fn prompt_password(label: &str, use_stdin: bool) -> CliResult<Secret> {
    if use_stdin {
        return Ok(Secret::new(read_stdin_line()?));
    }
    let value = rpassword::prompt_password(format!("{label}: "))?;
    Ok(Secret::new(value))
}

/// Prompt twice and require the two entries to match (used for a new *entry's* password via
/// `add`). Only checks non-emptiness/match — a stored entry's password is whatever the target
/// site actually requires (possibly a legacy weak one the user can't change), so the NIST
/// master-password rule below is deliberately **not** applied here; `vaultkeep check` is the
/// advisory (non-blocking) tool for flagging weak *stored* passwords (docs/11-compliance-mapping.md).
pub fn prompt_new_password(label: &str, use_stdin: bool) -> CliResult<Secret> {
    if use_stdin {
        let value = read_stdin_line()?;
        if value.is_empty() {
            return Err(vault_core::VaultError::InvalidInput("password must not be empty".into()).into());
        }
        return Ok(Secret::new(value));
    }
    loop {
        let first = rpassword::prompt_password(format!("{label}: "))?;
        let second = rpassword::prompt_password(format!("Confirm {label}: "))?;
        if first != second {
            eprintln!("Passwords did not match — try again.");
            continue;
        }
        if first.is_empty() {
            eprintln!("Password must not be empty — try again.");
            continue;
        }
        return Ok(Secret::new(first));
    }
}

/// Prompt twice for a *master* password (used by `init`/`passwd`) and enforce the NIST
/// SP 800-63B minimum-length/common-password rule (docs/11-compliance-mapping.md R-1/R-2) —
/// interactively, this retries in a loop with a friendly message; in `--stdin` mode it is a
/// hard failure, since a scripted caller should fail loudly rather than be silently retried.
pub fn prompt_new_master_password(label: &str, use_stdin: bool) -> CliResult<Secret> {
    if use_stdin {
        let value = read_stdin_line()?;
        vault_core::strength::validate_master_password(&value)?;
        return Ok(Secret::new(value));
    }
    loop {
        let first = rpassword::prompt_password(format!("{label}: "))?;
        let second = rpassword::prompt_password(format!("Confirm {label}: "))?;
        if first != second {
            eprintln!("Passwords did not match — try again.");
            continue;
        }
        if let Err(e) = vault_core::strength::validate_master_password(&first) {
            eprintln!("{e} — try again.");
            continue;
        }
        return Ok(Secret::new(first));
    }
}

/// Generate a strong master password instead of asking the user to type one, per current
/// guidance (NIST SP 800-63B / OWASP ASVS 5.0 V2.1 — a system-generated random secret of this
/// length comfortably clears the recommended entropy bar). Unlike an *entry's* password, the
/// master password is never stored anywhere in the vault format — it exists only in the user's
/// head or their own separate record — so it must be shown and explicitly acknowledged before
/// we proceed, or the vault becomes permanently unrecoverable the moment this prompt returns.
pub fn prompt_generated_master_password(length: u16, use_stdin: bool) -> CliResult<Secret> {
    let policy = vault_core::GeneratorPolicy { length, ..vault_core::GeneratorPolicy::default() };
    let password = vault_core::generator::generate_password(&policy)?;
    println!("Generated master password: {}", password.expose());
    println!(
        "This is shown once and is never stored anywhere — write it down or save it in a \
         separate password manager now. If you lose it, this vault cannot be recovered."
    );
    if use_stdin {
        // Scripted/CI caller: nothing to confirm interactively, the value is already on stdout.
        return Ok(password);
    }
    loop {
        if confirm("I have saved this password and am ready to continue")? {
            return Ok(password);
        }
        eprintln!("Save the password printed above, then confirm (or Ctrl+C to abort).");
    }
}

pub fn prompt_line(label: &str) -> CliResult<String> {
    use std::io::Write;
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

pub fn confirm(prompt: &str) -> CliResult<bool> {
    let answer = prompt_line(&format!("{prompt} [y/N]"))?;
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}
