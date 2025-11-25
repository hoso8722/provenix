use anyhow::Result;
use clap::{Parser, Subcommand};

mod config;
mod executor;

// Import provider crates to trigger their registration
extern crate provenix_attest;
extern crate provenix_sbom;
extern crate provenix_sign;
extern crate provenix_verify;

#[derive(Parser)]
#[command(name = "provenix", about = "Provenix CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    Sbom,
    Attest,
    Sign,
    Verify,
    Publish,
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();

    let cli = Cli::parse();
    let cfg = config::Config::load("provenix.yaml")?;
    match cli.command {
        Commands::Run => executor::pipeline::run_all(&cfg)?,
        Commands::Sbom => executor::sbom::run(&cfg)?,
        Commands::Attest => executor::attest::run(&cfg)?,
        Commands::Sign => executor::sign::run(&cfg)?,
        Commands::Verify => executor::verify::run(&cfg)?,
        Commands::Publish => executor::publish::run(&cfg)?,
    }
    Ok(())
}
