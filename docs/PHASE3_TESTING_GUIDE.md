# Phase 3 テストガイド

Phase 3 の実装をテストする方法について説明します。**Docker は不要**です。

## 📋 目次

1. [クイックテスト（推奨）](#1-クイックテスト推奨)
2. [完全テスト（Rekor 統合含む）](#2-完全テストrekor統合含む)
3. [手動テスト手順](#3-手動テスト手順)
4. [トラブルシューティング](#4-トラブルシューティング)

---

## 1. クイックテスト（推奨）

### 目的

- Phase 3 実装の後方互換性を確認
- インターネット接続不要
- 約 30 秒で完了

### 実行方法

```bash
# 1. スクリプトに実行権限を付与
chmod +x scripts/test-quick.sh

# 2. 実行
./scripts/test-quick.sh
```

### 何をテストするか

✅ Phase 2 互換モード（`rekor_url: null`）  
✅ SBOM 生成  
✅ Attestation 作成  
✅ Ed25519 署名  
✅ 署名検証  
✅ ハッシュチェーン検証

### 期待される出力

```
========================================
  Quick Test: Phase 2 Compatibility
  (No Rekor, No Internet Required)
========================================

🧹 Cleaning test directory...
🔑 Step 1/5: Generating keypair...
✅ Keypair generated

📦 Step 2/5: Generating SBOM...
✅ SBOM generated (316715 bytes)

📝 Step 3/5: Creating attestation...
✅ Attestation created (404088 bytes)

✍️  Step 4/5: Signing...
{
  "provider": "ed25519",
  "algorithm": "Ed25519",
  "output": "test-output-quick/signed-attestation.json",
  "signature_length": 64,
  "format": "in-toto DSSE"
}
✅ Signed (301453 bytes)

🔍 Step 5/5: Verifying...
{
  "valid": true,
  "provider": "ed25519",
  "algorithm": "Ed25519",
  "hash_chain_valid": true,
  "signature_valid": true,
  "rekor_verified": false,
  "subject": "provenix.sbom.json",
  "sbom_hash": "dc35787535fae7771b2b8b067f4a6819...",
  "timestamp": "2025-12-03T10:00:00Z"
}
✅ Verification PASSED

========================================
  ✨ Quick Test: SUCCESS
========================================
```

---

## 2. 完全テスト（Rekor 統合含む）

### 目的

- Rekor 透明性ログへのアップロードをテスト
- 公開 Sigstore サーバーとの統合を確認
- SLSA Level 3 機能を検証

### ⚠️ 重要な注意事項

このテストは**公開の Sigstore Rekor サーバー**にデータをアップロードします：

- ❗ **アップロードは永続的で削除できません**
- ❗ **データは全世界に公開されます**
- ❗ **プロジェクト名やビルド情報が含まれます**
- ✅ 秘密鍵や機密情報は含まれません（公開鍵とハッシュのみ）

### 実行方法

```bash
# 1. スクリプトに実行権限を付与
chmod +x scripts/test-phase3.sh

# 2. 実行（確認プロンプトが表示されます）
./scripts/test-phase3.sh
```

### テストフロー

```
Test 1: Phase 2互換性（Rekorなし）
  ├── 鍵生成
  ├── SBOM生成
  ├── Attestation作成
  ├── 署名（Rekorなし）
  └── 検証（Rekorなし）
  ✅ PASSED

Test 2: Rekor統合（公開サーバー）
  ├── 確認プロンプト → [y/N]
  ├── 鍵生成（新規）
  ├── SBOM生成
  ├── Attestation作成
  ├── 署名 + Rekorアップロード ⬆️
  ├── 検証 + Rekorチェック ⬇️
  └── メタデータ保存
  ✅ PASSED

Test 3: Rekorエントリーの手動確認
  ├── curl でエントリー取得
  ├── JSON保存
  └── jqで整形表示
  ✅ COMPLETED
```

### 期待される出力

```
=== Test 2: Rekor Integration (Public Sigstore) ===
⚠️  This test will upload to the PUBLIC Sigstore Rekor server
   The data will be permanently visible on the internet
Continue? (y/N): y

✍️  Signing with Rekor upload...
{
  "provider": "ed25519",
  "algorithm": "Ed25519",
  "output": "test-output-phase3/signed-attestation.json",
  "signature_length": 64,
  "format": "in-toto DSSE",
  "rekor": {
    "uuid": "24296fb24b8ad77a2fa9aeff5ca532de2f2d56a0ccf8e3fe0d710adc50843c5b45caf41ca7e1c77c",
    "log_index": 142857,
    "location": "https://rekor.sigstore.dev/api/v1/log/entries/24296fb...",
    "rekor_url": "https://rekor.sigstore.dev"
  }
}
✅ Rekor Upload Success:
   UUID: 24296fb24b8ad77a2fa9aeff5ca532de2f2d56a0ccf8e3fe0d710adc50843c5b45caf41ca7e1c77c
   Log Index: 142857
   URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb...

🔍 Verifying with Rekor check...
{
  "valid": true,
  "rekor_verified": true,
  "rekor": {
    "uuid": "24296fb...",
    "log_index": 142857,
    "integrated_time": 1701619200,
    "location": "https://rekor.sigstore.dev/api/v1/log/entries/24296fb..."
  }
}
✅ Test 2 Complete: Rekor verification passed

🌐 View on Rekor:
   https://search.sigstore.dev/?logIndex=142857
```

### 生成されるファイル

```
test-output-phase3/
├── keys/
│   ├── private.key          # Ed25519秘密鍵
│   └── public.key           # Ed25519公開鍵
├── sbom.json                # CycloneDX SBOM
├── attestation.json         # SLSA Provenance
├── signed-attestation.json  # DSSE署名済みエンベロープ
├── rekor-metadata.json      # Rekorアップロード結果
└── rekor-entry-raw.json     # Rekorから取得した生データ
```

---

## 3. 手動テスト手順

スクリプトを使わず、1 つずつコマンドを実行したい場合：

### ステップ 1: 環境準備

```bash
# テスト用ディレクトリを作成
rm -rf test-manual
mkdir -p test-manual/keys

# 設定ファイルを作成（Rekorなし）
cat > test-manual-config.json <<EOF
{
  "sbom": {
    "provider": "cargo-sbom",
    "target": ".",
    "output": "test-manual/sbom.json"
  },
  "attest": {
    "provider": "in-toto",
    "sbom_path": "test-manual/sbom.json",
    "output": "test-manual/attestation.json"
  },
  "sign": {
    "provider": "ed25519",
    "artifact_path": "test-manual/attestation.json",
    "key_path": "test-manual/keys/private.key",
    "output": "test-manual/signed-attestation.json",
    "rekor_url": null
  },
  "verify": {
    "provider": "ed25519",
    "artifact_path": "test-manual/sbom.json",
    "signature_path": "test-manual/signed-attestation.json",
    "rekor_url": null,
    "check_rekor": false
  }
}
EOF

# 設定ファイルを適用
cp provenix.yaml provenix.yaml.backup
cp test-manual-config.json provenix.yaml
```

### ステップ 2: 鍵生成

```bash
./target/release/provenix-keygen \
    --output test-manual/keys/private.key \
    --public test-manual/keys/public.key

# 確認
ls -la test-manual/keys/
```

### ステップ 3: SBOM 生成

```bash
./target/release/provenix-cli sbom

# 確認
ls -lh test-manual/sbom.json
head -20 test-manual/sbom.json
```

### ステップ 4: Attestation 作成

```bash
./target/release/provenix-cli attest

# 確認
ls -lh test-manual/attestation.json
```

### ステップ 5: 署名（Rekor なし）

```bash
./target/release/provenix-cli sign

# 確認
cat test-manual/signed-attestation.json | jq '.signatures[0].keyid'
```

### ステップ 6: 検証

```bash
./target/release/provenix-cli verify

# 期待される出力: "valid": true
```

### ステップ 7: Rekor 統合テスト（オプション）

```bash
# 設定を更新（Rekor有効化）
cat > test-manual-config.json <<EOF
{
  "sign": {
    "rekor_url": "https://rekor.sigstore.dev"
  },
  "verify": {
    "rekor_url": "https://rekor.sigstore.dev",
    "check_rekor": true
  }
}
EOF

# 再度署名（新しいSBOMで）
./target/release/provenix-cli sbom
./target/release/provenix-cli attest
./target/release/provenix-cli sign | jq '.rekor'

# Rekor検証
./target/release/provenix-cli verify | jq '.rekor_verified'
```

### クリーンアップ

```bash
# テストファイル削除
rm -rf test-manual

# 設定ファイルを復元
mv provenix.yaml.backup provenix.yaml
```

---

## 4. トラブルシューティング

### 問題 1: ビルドエラー

```
Error: provenix-cli not found
```

**解決策**:

```bash
cargo build --release
```

### 問題 2: 設定ファイルエラー

```
Error: Failed to parse config file
Caused by: trailing comma at line 7 column 5
```

**解決策**:
JSON の末尾カンマを削除してください：

```json
{
  "sign": {
    "rekor_url": null // ← カンマなし
  }
}
```

### 問題 3: Rekor アップロード失敗

```
Failed to upload to Rekor (continuing without transparency log):
Rekor upload failed: 503 - Service Unavailable
```

**原因**:

- Rekor サーバーが一時的にダウン
- ネットワーク接続エラー
- レート制限

**解決策**:

1. インターネット接続を確認
2. 数分待ってから再試行
3. Rekor サーバーのステータスを確認:
   ```bash
   curl https://rekor.sigstore.dev/api/v1/log
   ```

### 問題 4: Rekor 検証失敗

```
WARN Rekor verification failed (continuing):
No Rekor entry found for artifact hash: dc357875...
```

**原因**:

- 署名時に Rekor アップロードがスキップされた
- Rekor サーバーの同期遅延（通常 5-10 秒）

**解決策**:

1. 署名ログで Rekor UUID を確認:

   ```bash
   grep "Uploaded to Rekor" sign.log
   ```

2. 手動でエントリーを確認:

   ```bash
   SBOM_HASH=$(sha256sum test-output/sbom.json | cut -d' ' -f1)
   curl -X POST https://rekor.sigstore.dev/api/v1/index/retrieve \
     -H "Content-Type: application/json" \
     -d "{\"hash\": \"sha256:${SBOM_HASH}\"}"
   ```

3. 数秒待ってから再検証

### 問題 5: 非同期ランタイムエラー

```
ERROR Failed to create async runtime: Cannot start a runtime from within a runtime
```

**解決策**:
これはコード内部の問題です。以下を確認:

1. Cargo.toml の tokio 依存関係
2. 既存の tokio ランタイムとの衝突

**回避策**:

```bash
# 環境変数で調整
TOKIO_WORKER_THREADS=1 ./target/release/provenix-cli sign
```

---

## 推奨テスト順序

### 初回テスト

1. ✅ **クイックテスト** - 後方互換性確認（5 分）
2. ✅ **手動テスト** - 各ステップを理解（10 分）
3. ⏸️ **Rekor 統合** - 公開アップロードの確認（判断保留）

### 開発中のテスト

- 毎回: `./scripts/test-quick.sh`（30 秒）
- 大きな変更後: `./scripts/test-phase3.sh`（スキップ可）

### CI/CD 統合

```yaml
# .github/workflows/test.yml
jobs:
  test-phase3:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: cargo build --release
      - name: Quick Test
        run: ./scripts/test-quick.sh
      # Rekorテストはスキップ（公開アップロードのため）
```

---

## まとめ

### Docker が不要な理由

- ✅ すべてのコンポーネントがネイティブ Rust バイナリ
- ✅ 外部依存は既にインストール済み（cargo-sbom、Syft）
- ✅ Rekor API は HTTPS で直接アクセス可能
- ✅ テスト環境が軽量（テストディレクトリのみ）

### テスト推奨事項

1. **最初は必ずクイックテスト**

   - 基本機能の確認
   - 後方互換性の確認
   - 問題の早期発見

2. **Rekor 統合は慎重に**

   - 公開データになることを理解
   - 必要な場合のみ実行
   - 本番環境では自動化

3. **手動テストで理解を深める**
   - 各ステップの出力を確認
   - エラーメッセージの理解
   - デバッグスキルの向上

---

**次のステップ**: Phase 4 実装前に、まず`./scripts/test-quick.sh`を実行して Phase 3 の動作を確認してください。
