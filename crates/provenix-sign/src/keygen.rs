use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "provenix-keygen")]
#[command(about = "Generate Ed25519 keypair for signing attestations")]
struct Cli {
    /// Output directory for keys
    #[arg(short, long, default_value = "keys")]
    output: PathBuf,

    /// Private key filename
    #[arg(long, default_value = "private.key")]
    private_name: String,

    /// Public key filename
    #[arg(long, default_value = "public.key")]
    public_name: String,
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    println!("🔐 Generating Ed25519 keypair...");

    // Generate keypair
    let (_, private_key_bytes, public_key_bytes) = provenix_sign::generate_keypair()?;

    // Create output paths
    let private_path = cli.output.join(&cli.private_name);
    let public_path = cli.output.join(&cli.public_name);

    // Save keypair
    provenix_sign::save_keypair(
        &private_key_bytes,
        &public_key_bytes,
        &private_path,
        &public_path,
    )?;

    println!("\n✅ Keypair generated successfully!");
    println!("   Private key: {:?}", private_path);
    println!("   Public key:  {:?}", public_path);
    println!("\n⚠️  Keep your private key secure!");
    println!("   The private key is stored with 0600 permissions (owner read/write only)");
    println!("\n📋 Usage:");
    println!("   Sign:   provenix-cli sign --key {:?}", private_path);
    println!("   Verify: provenix-cli verify --key {:?}", public_path);

    Ok(())
}
