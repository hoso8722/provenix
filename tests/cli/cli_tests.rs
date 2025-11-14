use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_px_help_command() {
    let mut cmd = Command::cargo_bin("px").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Provenix CLI"));
}

#[test]
fn test_px_version_command() {
    let mut cmd = Command::cargo_bin("px").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_pxb_help_command() {
    let mut cmd = Command::cargo_bin("pxb").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("SBOM tool"));
}

#[test]
fn test_pxa_help_command() {
    let mut cmd = Command::cargo_bin("pxa").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Attestation tool"));
}

#[test]
fn test_pxs_help_command() {
    let mut cmd = Command::cargo_bin("pxs").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Server"));
}

#[test]
fn test_invalid_command() {
    let mut cmd = Command::cargo_bin("px").unwrap();
    cmd.arg("invalid-command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn test_config_file_handling() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    fs::write(&config_path, "[server]\nport = 8080\n").unwrap();
    
    let mut cmd = Command::cargo_bin("px").unwrap();
    cmd.arg("config")
        .arg("--file")
        .arg(&config_path)
        .arg("validate")
        .assert()
        .success();
}

#[test]
fn test_output_formats() {
    let mut cmd = Command::cargo_bin("pxb").unwrap();
    cmd.arg("generate")
        .arg("--format")
        .arg("json")
        .arg("--dry-run")
        .assert()
        .success();
    
    let mut cmd = Command::cargo_bin("pxb").unwrap();
    cmd.arg("generate")
        .arg("--format")
        .arg("xml")
        .arg("--dry-run")
        .assert()
        .success();
}