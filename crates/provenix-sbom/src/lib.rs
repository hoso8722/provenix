use provenix_plugin::SbomProvider;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

// ===== Built-in Provider: cargo-sbom =====

pub struct CargoSbomProvider;

impl SbomProvider for CargoSbomProvider {
    fn name(&self) -> &str {
        "cargo-sbom"
    }

    fn generate(&self, target: &str, output: &PathBuf) -> anyhow::Result<serde_json::Value> {
        log::info!("Generating SBOM using cargo-sbom for target: {}", target);

        // Ensure output directory exists
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Run cargo-sbom command
        let output_str = output.to_string_lossy();
        let result = Command::new("cargo")
            .args(&[
                "sbom",
                "--project-directory",
                target,
                "--output-format",
                "cyclone_dx_json_1_5",
            ])
            .output();

        match result {
            Ok(out) if out.status.success() => {
                // Write stdout to output file
                std::fs::write(output, &out.stdout)?;
                log::info!("SBOM generated successfully at: {}", output_str);
                Ok(json!({
                    "provider": "cargo-sbom",
                    "format": "cyclonedx",
                    "output": output_str,
                    "target": target
                }))
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!(
                    "cargo-sbom failed with exit code: {:?}\n{}",
                    out.status.code(),
                    stderr
                )
            }
            Err(e) => {
                anyhow::bail!("Failed to execute cargo-sbom: {}. Make sure cargo-sbom is installed: cargo install cargo-sbom", e)
            }
        }
    }
}

// ===== External Provider: Syft =====

pub struct SyftProvider;    

impl SbomProvider for SyftProvider {
    fn name(&self) -> &str {
        "syft"
    }

    fn generate(&self, target: &str, output: &PathBuf) -> anyhow::Result<serde_json::Value> {
        log::info!("Generating SBOM using Syft for target: {}", target);

        // Check if syft is installed
        provenix_utils::tool_manager::ToolManager::ensure_installed("syft")?;

        // Ensure output directory exists
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Run syft command
        let output_str = output.to_string_lossy();
        let result = Command::new("syft")
            .args(&[target, "-o", "cyclonedx-json", "--file", &output_str])
            .output();

        match result {
            Ok(out) if out.status.success() => {
                log::info!("SBOM generated successfully with Syft at: {}", output_str);
                Ok(json!({
                    "provider": "syft",
                    "format": "cyclonedx",
                    "output": output_str,
                    "target": target
                }))
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!(
                    "Syft failed with exit code: {:?}\n{}",
                    out.status.code(),
                    stderr
                )
            }
            Err(e) => {
                anyhow::bail!("Failed to execute syft: {}", e)
            }
        }
    }
}

#[ctor::ctor]
fn register_cargo_sbom() {
    let _ = provenix_core::registry::register_sbom("cargo-sbom", CargoSbomProvider);
}

#[ctor::ctor]
fn register_syft() {
    let _ = provenix_core::registry::register_sbom("syft", SyftProvider);
}
