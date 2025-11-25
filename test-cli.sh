#!/bin/bash

# Provenix CLI Test Script
# テスト用のスクリプト

set -e

echo "🚀 Provenix CLI テスト開始"
echo "================================"

# ビルド
echo -e "\n📦 ビルド中..."
cargo build --bin provenix-cli --quiet

# ヘルプ表示
echo -e "\n📖 ヘルプ表示:"
cargo run --bin provenix-cli --quiet -- --help

# 各コマンドのテスト
echo -e "\n🔍 SBOM生成テスト:"
RUST_LOG=info cargo run --bin provenix-cli --quiet -- sbom 2>&1 | grep INFO

echo -e "\n📝 Attestation作成テスト:"
RUST_LOG=info cargo run --bin provenix-cli --quiet -- attest 2>&1 | grep INFO

echo -e "\n✍️  署名テスト:"
RUST_LOG=info cargo run --bin provenix-cli --quiet -- sign 2>&1 | grep INFO

echo -e "\n✅ 検証テスト:"
RUST_LOG=info cargo run --bin provenix-cli --quiet -- verify 2>&1 | grep INFO

echo -e "\n📤 公開テスト:"
RUST_LOG=info cargo run --bin provenix-cli --quiet -- publish 2>&1 | grep -E "(INFO|WARN)"

echo -e "\n================================"
echo "✅ 全てのテストが正常に完了しました！"
