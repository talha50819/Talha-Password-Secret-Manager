use crate::cli_error::CliResult;
use clap::CommandFactory;
use clap_complete::{generate, Shell};

pub fn run(shell: Shell) -> CliResult<()> {
    let mut cmd = crate::Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}
