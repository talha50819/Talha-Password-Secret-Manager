use crate::cli_error::CliResult;
use vault_core::generator;
use vault_core::GeneratorPolicy;

#[allow(clippy::too_many_arguments)]
pub fn run(
    length: u16,
    no_upper: bool,
    no_lower: bool,
    no_digits: bool,
    no_symbols: bool,
    allow_ambiguous: bool,
    count: usize,
) -> CliResult<()> {
    let policy = GeneratorPolicy {
        length,
        use_upper: !no_upper,
        use_lower: !no_lower,
        use_digits: !no_digits,
        use_symbols: !no_symbols,
        avoid_ambiguous: !allow_ambiguous,
    };
    let passwords = generator::generate_many(&policy, count)?;
    for p in passwords {
        println!("{}", p.expose());
    }
    Ok(())
}
