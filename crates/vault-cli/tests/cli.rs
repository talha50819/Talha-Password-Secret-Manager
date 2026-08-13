//! End-to-end CLI integration tests (Phase 7 — docs/04-backlog.md US covering Epic 2/3/4 DoD).
//! Exercises the real compiled `vaultkeep` binary via `assert_cmd`, using `--stdin` for
//! non-interactive secret input (see docs/cli-reference.md).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const MASTER: &str = "Correct-Horse-Battery-Staple-9!";

struct Vault {
    _dir: TempDir,
    path: PathBuf,
}

fn new_vault() -> Vault {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.vkl");
    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["--vault", path.to_str().unwrap(), "--stdin", "init", "--kdf-profile", "interactive"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();
    Vault { _dir: dir, path }
}

fn vk(vault: &Vault) -> Command {
    let mut cmd = Command::cargo_bin("vaultkeep").unwrap();
    cmd.args(["--vault", vault.path.to_str().unwrap(), "--stdin"]);
    cmd
}

#[test]
fn init_refuses_to_overwrite_existing_vault() {
    let vault = new_vault();
    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["--vault", vault.path.to_str().unwrap(), "--stdin", "init"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn opening_missing_vault_exits_4() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nope.vkl");
    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["--vault", path.to_str().unwrap(), "--stdin", "list"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure()
        .code(4);
}

#[test]
fn wrong_master_password_exits_3_with_generic_message() {
    let vault = new_vault();
    vk(&vault)
        .args(["list"])
        .write_stdin("totally-wrong-password\n")
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("authentication failed"));
}

#[test]
fn add_get_list_search_edit_remove_round_trip() {
    let vault = new_vault();

    vk(&vault)
        .args(["add", "github.com", "--username", "alice", "--url", "https://github.com", "--tag", "dev"])
        .write_stdin(format!("{MASTER}\nGhP@ssw0rd123!\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Added entry"));

    vk(&vault)
        .args(["get", "github.com", "--field", "password", "--show"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("GhP@ssw0rd123!"));

    vk(&vault)
        .args(["list"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("github.com").and(predicate::str::contains("alice")))
        // list must never leak the password
        .stdout(predicate::str::contains("GhP@ssw0rd123!").not());

    vk(&vault)
        .args(["search", "git"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("github.com"));

    vk(&vault)
        .args(["edit", "github.com", "--username", "alice2", "--tag", "dev", "--tag", "work"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();

    vk(&vault)
        .args(["get", "github.com", "--field", "username", "--show"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("alice2"));

    vk(&vault)
        .args(["remove", "github.com", "--force"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();

    vk(&vault)
        .args(["get", "github.com", "--show"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no entry matches"));
}

#[test]
fn duplicate_title_is_rejected() {
    let vault = new_vault();
    vk(&vault).args(["add", "dup", "--generate"]).write_stdin(format!("{MASTER}\n")).assert().success();
    vk(&vault)
        .args(["add", "dup", "--generate"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn list_json_is_valid_json_and_excludes_passwords() {
    let vault = new_vault();
    vk(&vault)
        .args(["add", "site.com", "--generate"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();

    let output = vk(&vault).args(["--json", "list"]).write_stdin(format!("{MASTER}\n")).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(parsed.is_array());
    assert_eq!(parsed[0]["title"], "site.com");
    assert!(parsed[0].get("password").is_none());
}

#[test]
fn generate_respects_length_and_count_without_touching_any_vault() {
    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["generate", "--length", "24", "--count", "5"])
        .assert()
        .success()
        .stdout(predicate::function(|s: &str| s.lines().filter(|l| !l.is_empty()).count() == 5))
        .stdout(predicate::function(|s: &str| s.lines().all(|l| l.is_empty() || l.chars().count() == 24)));
}

#[test]
fn check_flags_a_common_password() {
    let vault = new_vault();
    vk(&vault).args(["add", "weak-site"]).write_stdin(format!("{MASTER}\npassword1\n")).assert().success();

    vk(&vault)
        .args(["check", "--all"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("VeryWeak"));
}

#[test]
fn audit_log_never_contains_plaintext_secrets_or_titles() {
    let vault = new_vault();
    vk(&vault)
        .args(["add", "very-sensitive-title", "--username", "sensitive-user"])
        .write_stdin(format!("{MASTER}\nsuper-secret-plaintext-pw\n"))
        .assert()
        .success();

    let audit_path = vault.path.with_file_name(format!("{}.audit.log", vault.path.file_name().unwrap().to_str().unwrap()));
    let contents = std::fs::read_to_string(audit_path).unwrap();
    assert!(!contents.contains("very-sensitive-title"));
    assert!(!contents.contains("sensitive-user"));
    assert!(!contents.contains("super-secret-plaintext-pw"));
    assert!(contents.contains("ADD") || contents.contains("Add"));
}

#[test]
fn passwd_rekeys_and_old_password_stops_working() {
    let vault = new_vault();
    vk(&vault).args(["add", "x", "--generate"]).write_stdin(format!("{MASTER}\n")).assert().success();

    vk(&vault)
        .args(["passwd"])
        .write_stdin(format!("{MASTER}\nNew-Master-Pass-1!\n"))
        .assert()
        .success();

    vk(&vault).args(["list"]).write_stdin(format!("{MASTER}\n")).assert().failure().code(3);

    vk(&vault)
        .args(["list"])
        .write_stdin("New-Master-Pass-1!\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("x"));
}

#[test]
fn export_then_import_into_a_fresh_vault_round_trips_entries() {
    let vault = new_vault();
    vk(&vault)
        .args(["add", "carried-over", "--username", "u"])
        .write_stdin(format!("{MASTER}\nCarried0verPw!\n"))
        .assert()
        .success();

    let backup_dir = TempDir::new().unwrap();
    let backup_path = backup_dir.path().join("backup.vkl");
    vk(&vault)
        .args(["export", "--output", backup_path.to_str().unwrap()])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();

    let vault2 = new_vault();
    vk(&vault2)
        .args(["import", backup_path.to_str().unwrap()])
        .write_stdin(format!("{MASTER}\n{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 1"));

    vk(&vault2)
        .args(["get", "carried-over", "--field", "password", "--show"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Carried0verPw!"));
}

#[test]
fn keyfile_bound_vault_requires_the_keyfile() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("kf.vkl");
    let keyfile_path = dir.path().join("key.bin");
    std::fs::write(&keyfile_path, b"some-keyfile-bytes-not-a-password").unwrap();

    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["--vault", vault_path.to_str().unwrap(), "--keyfile", keyfile_path.to_str().unwrap(), "--stdin", "init"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();

    // without the keyfile: refused
    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["--vault", vault_path.to_str().unwrap(), "--stdin", "list"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure();

    // with the keyfile: works
    Command::cargo_bin("vaultkeep")
        .unwrap()
        .args(["--vault", vault_path.to_str().unwrap(), "--keyfile", keyfile_path.to_str().unwrap(), "--stdin", "list"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();
}

#[test]
fn help_mentions_every_documented_command() {
    let output = Command::cargo_bin("vaultkeep").unwrap().arg("--help").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for cmd in [
        "init", "add", "get", "list", "search", "edit", "remove", "generate", "check", "totp", "passwd", "export",
        "import", "audit-log", "shell", "completions",
    ] {
        assert!(stdout.contains(cmd), "--help output missing documented command '{cmd}'");
    }
}
