//! External tool management for better UX

use anyhow::{Context, Result};
use std::process::Command;

pub struct ToolManager;

impl ToolManager {
    /// Check if a tool is installed
    pub fn check_installed(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get tool version
    pub fn get_version(tool: &str) -> Result<String> {
        let output = Command::new(tool)
            .arg("--version")
            .output()
            .context(format!("Failed to get version of {}", tool))?;

        if !output.status.success() {
            anyhow::bail!("{} --version failed", tool);
        }

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }

    /// Ensure tool is installed, show helpful message if not
    pub fn ensure_installed(tool: &str) -> Result<()> {
        if Self::check_installed(tool) {
            log::debug!("{} is installed", tool);
            Ok(())
        } else {
            Self::show_install_instructions(tool)?;
            anyhow::bail!("{} is not installed", tool)
        }
    }

    /// Ensure tool is installed with auto-install option
    pub fn ensure_installed_with_auto(tool: &str, auto_install: bool) -> Result<()> {
        if Self::check_installed(tool) {
            log::debug!("{} is installed", tool);
            return Ok(());
        }

        if auto_install {
            eprintln!("🤖 Auto-installing {}...", tool);
            Self::auto_install(tool)?;

            // Verify installation
            if Self::check_installed(tool) {
                log::info!("✅ {} is now available", tool);
                Ok(())
            } else {
                anyhow::bail!("{} installation failed or not in PATH", tool)
            }
        } else {
            Self::show_install_instructions(tool)?;
            eprintln!("\n💡 Tip: Use --auto-install flag to install automatically");
            anyhow::bail!("{} is not installed", tool)
        }
    }

    /// Show installation instructions for a tool
    fn show_install_instructions(tool: &str) -> Result<()> {
        eprintln!("\n❌ {} is not installed.\n", tool);
        eprintln!("📦 Installation instructions:");

        match tool {
            "syft" => {
                eprintln!("  macOS:    brew install syft");
                eprintln!("  Linux:    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin");
                eprintln!("  Windows:  scoop install syft");
                eprintln!("            (or: choco install syft)");
                eprintln!("\n  Documentation: https://github.com/anchore/syft");
            }
            "trivy" => {
                eprintln!("  macOS:    brew install trivy");
                eprintln!("  Linux:    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin");
                eprintln!("  Windows:  scoop install trivy");
                eprintln!("            (or: choco install trivy)");
                eprintln!("\n  Documentation: https://github.com/aquasecurity/trivy");
            }
            "cosign" => {
                eprintln!("  macOS:    brew install cosign");
                eprintln!("  Linux:    curl -sL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign");
                eprintln!("  Windows:  scoop install cosign");
                eprintln!("            (or: choco install cosign)");
                eprintln!("\n  Documentation: https://github.com/sigstore/cosign");
            }
            _ => {
                eprintln!("  Please install {} manually", tool);
            }
        }

        eprintln!("\n💡 Tip: You can use the built-in provider instead:");
        eprintln!("  Edit provenix.yaml and change provider to 'cargo-sbom' (for SBOM)");

        Ok(())
    }

    /// Auto-install tool (requires user permission)
    #[cfg(target_os = "macos")]
    pub fn auto_install(tool: &str) -> Result<()> {
        log::info!("🔧 Installing {} via Homebrew...", tool);

        let status = Command::new("brew")
            .args(&["install", tool])
            .status()
            .context("Failed to run brew")?;

        if !status.success() {
            anyhow::bail!("Failed to install {} via Homebrew", tool);
        }

        log::info!("✅ {} installed successfully!", tool);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn auto_install(tool: &str) -> Result<()> {
        log::info!("🔧 Installing {}...", tool);

        let install_script = match tool {
            "syft" => "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
            "trivy" => "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
            "cosign" => "curl -sL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign",
            _ => anyhow::bail!("Auto-install not supported for {}", tool),
        };

        let status = Command::new("sh")
            .arg("-c")
            .arg(install_script)
            .status()
            .context(format!("Failed to install {}", tool))?;

        if !status.success() {
            anyhow::bail!("Failed to install {}", tool);
        }

        log::info!("✅ {} installed successfully!", tool);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn auto_install(tool: &str) -> Result<()> {
        log::info!("🔧 Installing {} on Windows...", tool);

        // Try Scoop first (most common on Windows)
        if Self::check_installed("scoop") {
            log::info!("Using Scoop to install {}", tool);
            let status = Command::new("scoop")
                .args(&["install", tool])
                .status()
                .context("Failed to run scoop")?;

            if status.success() {
                log::info!("✅ {} installed successfully via Scoop!", tool);
                return Ok(());
            }
        }

        // Try Chocolatey as fallback
        if Self::check_installed("choco") {
            log::info!("Using Chocolatey to install {}", tool);
            let status = Command::new("choco")
                .args(&["install", tool, "-y"])
                .status()
                .context("Failed to run choco")?;

            if status.success() {
                log::info!("✅ {} installed successfully via Chocolatey!", tool);
                return Ok(());
            }
        }

        // Manual installation as last resort
        log::warn!("No package manager found (Scoop or Chocolatey)");
        Self::manual_install_windows(tool)
    }

    #[cfg(target_os = "windows")]
    fn manual_install_windows(tool: &str) -> Result<()> {
        use std::env;
        use std::fs;

        log::info!("Attempting manual installation of {}", tool);

        let (download_url, binary_name) = match tool {
            "syft" => (
                "https://github.com/anchore/syft/releases/latest/download/syft_windows_amd64.zip",
                "syft.exe",
            ),
            "trivy" => (
                "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_windows-64bit.zip",
                "trivy.exe",
            ),
            "cosign" => (
                "https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe",
                "cosign.exe",
            ),
            _ => anyhow::bail!("Manual install not supported for {}", tool),
        };

        // Download using PowerShell
        let local_appdata =
            env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        let install_dir = format!("{}\\provenix\\bin", local_appdata);
        fs::create_dir_all(&install_dir)?;

        let output_file = format!("{}\\{}", install_dir, binary_name);

        log::info!("Downloading {} to {}", tool, output_file);

        let ps_script = if download_url.ends_with(".zip") {
            format!(
                "Invoke-WebRequest -Uri '{}' -OutFile '{}.zip'; \
                 Expand-Archive -Path '{}.zip' -DestinationPath '{}' -Force; \
                 Remove-Item '{}.zip'",
                download_url, output_file, output_file, install_dir, output_file
            )
        } else {
            format!(
                "Invoke-WebRequest -Uri '{}' -OutFile '{}'",
                download_url, output_file
            )
        };

        let status = Command::new("powershell")
            .args(&["-Command", &ps_script])
            .status()
            .context("Failed to run PowerShell")?;

        if !status.success() {
            anyhow::bail!("Failed to download {}", tool);
        }

        // Add to PATH instruction
        eprintln!("\n⚠️  Please add to your PATH:");
        eprintln!("   {}", install_dir);
        eprintln!("\n   Or run in PowerShell:");
        eprintln!("   $env:Path += ';{}'", install_dir);

        log::info!("✅ {} installed to {}", tool, output_file);
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    pub fn auto_install(_tool: &str) -> Result<()> {
        anyhow::bail!("Auto-install is not supported on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_cargo_installed() {
        // cargo should always be installed in a Rust environment
        assert!(ToolManager::check_installed("cargo"));
    }

    #[test]
    fn test_get_cargo_version() {
        let version = ToolManager::get_version("cargo");
        assert!(version.is_ok());
        assert!(version.unwrap().contains("cargo"));
    }
}
