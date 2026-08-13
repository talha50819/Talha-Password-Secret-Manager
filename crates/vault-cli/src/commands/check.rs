use crate::cli_error::CliResult;
use vault_core::strength::{self, StrengthReport};
use vault_core::{Entry, VaultStore};

fn print_report(title: &str, report: &StrengthReport, json: bool) -> CliResult<()> {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "title": title,
                "level": format!("{:?}", report.level),
                "estimated_bits": report.estimated_bits,
                "is_common_password": report.is_common_password,
                "reused_in": report.reused_in,
                "age_days": report.age_days,
                "stale": report.stale,
            })
        );
        return Ok(());
    }
    let mut flags = Vec::new();
    if report.is_common_password {
        flags.push("COMMON".to_string());
    }
    if !report.reused_in.is_empty() {
        flags.push(format!("REUSED x{}", report.reused_in.len()));
    }
    if report.stale {
        flags.push("STALE".to_string());
    }
    let flag_str = if flags.is_empty() { String::new() } else { format!("  [{}]", flags.join(", ")) };
    println!("{:<28} {:>10?}  ~{:.0} bits{flag_str}", title, report.level, report.estimated_bits);
    Ok(())
}

pub fn run(store: &VaultStore, title: Option<&str>, all: bool, json: bool, stale_after_days: i64) -> CliResult<()> {
    let now = chrono::Utc::now();
    let entries: &[Entry] = store.entries();

    match title {
        Some(t) if !all => {
            let entry = store.get_entry(t)?;
            let report = strength::assess_entry(entry, entries, stale_after_days, now);
            print_report(&entry.title, &report, json)?;
        }
        _ => {
            for entry in entries {
                let report = strength::assess_entry(entry, entries, stale_after_days, now);
                print_report(&entry.title, &report, json)?;
            }
        }
    }
    Ok(())
}
