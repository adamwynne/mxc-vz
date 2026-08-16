//! `vz-exec` — the MXC executor binary for the vz backend (SDK wiring,
//! Phase 5). See `lib.rs` for the CLI contract.

use std::process;

fn main() {
    let cli = match vz_exec::parse_args(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("Error: {}\n{}", error.0, vz_exec::USAGE);
            process::exit(2);
        }
    };
    process::exit(vz_exec::run(&cli));
}
