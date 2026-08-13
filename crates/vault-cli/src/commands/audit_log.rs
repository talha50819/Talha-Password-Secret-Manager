use crate::cli_error::CliResult;
use vault_core::VaultStore;

pub fn run(store: &VaultStore, tail: usize, json: bool) -> CliResult<()> {
    let records = store.audit().tail(tail)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }
    if records.is_empty() {
        println!("(no audit records)");
        return Ok(());
    }
    for record in records {
        let entry_id = record.entry_id.map(|id| id.to_string()).unwrap_or_else(|| "-".to_string());
        println!("{}  {:<16?}  {}", record.ts.to_rfc3339(), record.op, entry_id);
    }
    Ok(())
}
