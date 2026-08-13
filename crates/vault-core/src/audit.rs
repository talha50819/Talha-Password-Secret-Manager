//! Local, append-only audit trail.
//!
//! By construction this module's public logging function accepts only an `AuditOp` and an
//! optional `Uuid` — never an `Entry` or any string field from one — so a call site cannot
//! accidentally leak a title, username, password, or note into the log file. See
//! docs/data-model.md "Audit log record" and docs/03-threat-model.md T3.

use crate::error::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditOp {
    Init,
    UnlockSuccess,
    UnlockFailed,
    Add,
    Get,
    Edit,
    Delete,
    Export,
    Import,
    PasswordChanged,
    Rekey,
    Lock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: chrono::DateTime<Utc>,
    pub op: AuditOp,
    pub entry_id: Option<Uuid>,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        AuditLog { path: path.into() }
    }

    pub fn log(&self, op: AuditOp, entry_id: Option<Uuid>) -> Result<()> {
        let record = AuditRecord { ts: Utc::now(), op, entry_id };
        let line = serde_json::to_string(&record).map_err(|_| crate::error::VaultError::Serialization)?;

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }

        writeln!(f, "{line}")?;
        Ok(())
    }

    pub fn tail(&self, n: usize) -> Result<Vec<AuditRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let all: Vec<AuditRecord> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let start = all.len().saturating_sub(n);
        Ok(all[start..].to_vec())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn log_and_tail_round_trip() {
        let dir = tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));
        log.log(AuditOp::Init, None).unwrap();
        let id = Uuid::new_v4();
        log.log(AuditOp::Add, Some(id)).unwrap();

        let records = log.tail(10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].op, AuditOp::Add);
        assert_eq!(records[1].entry_id, Some(id));
    }

    #[test]
    fn tail_respects_limit() {
        let dir = tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));
        for _ in 0..5 {
            log.log(AuditOp::Get, None).unwrap();
        }
        assert_eq!(log.tail(2).unwrap().len(), 2);
    }
}
