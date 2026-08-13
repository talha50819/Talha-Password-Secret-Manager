use crate::cli_error::CliResult;
use crate::prompt;
use std::time::Duration;
use vault_core::{EntryPatch, EntrySummary, NewEntry, VaultError, VaultStore};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum FieldArg {
    Password,
    Username,
    Url,
    Notes,
    Totp,
}

#[allow(clippy::too_many_arguments)]
pub fn add(
    store: &mut VaultStore,
    title: String,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    generate: bool,
    length: u16,
    use_stdin: bool,
) -> CliResult<()> {
    let password = if generate {
        let mut policy = store.settings().generator_defaults.clone();
        policy.length = length;
        vault_core::generator::generate_password(&policy)?
    } else {
        prompt::prompt_new_password("Entry password", use_stdin)?
    };
    let id = store.add_entry(NewEntry { title, username, password, url, notes, tags, totp_seed: None })?;
    println!("Added entry {id}");
    Ok(())
}

pub fn get(store: &VaultStore, title: &str, field: FieldArg, show: bool, clipboard_clear_secs: u32) -> CliResult<()> {
    let entry = store.get_entry_audited(title)?;

    if matches!(field, FieldArg::Totp) {
        let seed = entry
            .totp_seed
            .as_ref()
            .ok_or_else(|| VaultError::InvalidInput("this entry has no TOTP seed".into()))?;
        let code = vault_core::totp::current_code_now(seed.expose())?;
        println!("{} (expires in {}s)", code.code, code.seconds_remaining);
        return Ok(());
    }

    let value = match field {
        FieldArg::Password => entry.password.expose().to_string(),
        FieldArg::Username => entry.username.clone().unwrap_or_default(),
        FieldArg::Url => entry.url.clone().unwrap_or_default(),
        FieldArg::Notes => entry.notes.clone().unwrap_or_default(),
        FieldArg::Totp => unreachable!(),
    };

    if show {
        println!("{value}");
        return Ok(());
    }

    match crate::clipboard::copy_with_autoclear(&value, Duration::from_secs(clipboard_clear_secs as u64)) {
        Ok(()) => println!("Copied to clipboard; clearing automatically in {clipboard_clear_secs}s."),
        Err(e) => {
            eprintln!("Warning: {e} — printing instead.");
            println!("{value}");
        }
    }
    Ok(())
}

fn print_summaries(items: &[EntrySummary], json: bool) -> CliResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("(no entries)");
        return Ok(());
    }
    for item in items {
        let user = item.username.as_deref().unwrap_or("-");
        let tags = if item.tags.is_empty() { String::from("-") } else { item.tags.join(",") };
        let totp = if item.has_totp { " [totp]" } else { "" };
        println!("{:<8} {:<28} {:<20} {}{}", &item.id.to_string()[..8], item.title, user, tags, totp);
    }
    Ok(())
}

pub fn list(store: &VaultStore, tag: Option<&str>, json: bool) -> CliResult<()> {
    print_summaries(&store.list(tag), json)
}

pub fn search(store: &VaultStore, query: &str, json: bool) -> CliResult<()> {
    print_summaries(&store.search(query), json)
}

#[allow(clippy::too_many_arguments)]
pub fn edit(
    store: &mut VaultStore,
    title: &str,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    regenerate: bool,
    length: u16,
) -> CliResult<()> {
    let clear_or_set = |s: String| if s.is_empty() { None } else { Some(s) };
    let mut patch = EntryPatch::default();
    if let Some(u) = username {
        patch.username = Some(clear_or_set(u));
    }
    if let Some(u) = url {
        patch.url = Some(clear_or_set(u));
    }
    if let Some(n) = notes {
        patch.notes = Some(clear_or_set(n));
    }
    if !tags.is_empty() {
        patch.tags = Some(tags);
    }
    if regenerate {
        let mut policy = store.settings().generator_defaults.clone();
        policy.length = length;
        patch.password = Some(vault_core::generator::generate_password(&policy)?);
    }
    store.edit_entry(title, patch)?;
    println!("Updated entry '{title}'.");
    Ok(())
}

pub fn remove(store: &mut VaultStore, title: &str, force: bool) -> CliResult<()> {
    if !force && !prompt::confirm(&format!("Delete entry '{title}'?"))? {
        println!("Aborted.");
        return Ok(());
    }
    store.remove_entry(title)?;
    println!("Deleted entry '{title}'.");
    Ok(())
}
