#!/usr/bin/env bash
set -euo pipefail

CRATES=(provenix-cli provenix-core provenix-sbom provenix-attest provenix-sign provenix-verify provenix-plugin provenix-utils)

for c in "${CRATES[@]}"; do
  DIR="crates/$c"
  mkdir -p "$DIR/src"
  cat > "$DIR/Cargo.toml" <<EOF
[package]
name = "$c"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
anyhow = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
log = { workspace = true }

# crate-specific deps
[target.'cfg(unix)'.dependencies]
# add platform specific if needed

EOF

  # create lib or main placeholder if not exist
  if [[ "$c" == "provenix-cli" ]]; then
    # create binary target
    cat > "$DIR/src/main.rs" <<'RS'
fn main() -> anyhow::Result<()> {
    println!("provenix cli bootstrap");
    Ok(())
}
RS
  else
    cat > "$DIR/src/lib.rs" <<'RS'
pub fn hello() -> &'static str {
    "hello from crate"
}
RS
  fi

  echo "Created $DIR/Cargo.toml and src/"
done

echo "Done generating crate templates."