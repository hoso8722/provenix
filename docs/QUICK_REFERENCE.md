# Provenix クイックリファレンス

## 🚀 1 分でわかる Provenix

Provenix は**ソフトウェアサプライチェーンセキュリティプラットフォーム**です。

### 何ができる？

- ✅ SBOM（ソフトウェア部品表）を自動生成
- ✅ ビルドプロセスを暗号学的に証明（アテステーション）
- ✅ 成果物にデジタル署名
- ✅ 署名とアテステーションを検証

---

## 📦 コンポーネント一覧

| 名前            | 役割                         | バイナリ     | 状態 |
| --------------- | ---------------------------- | ------------ | ---- |
| provenix-core   | コアライブラリ（レジストリ） | -            | ✅   |
| provenix-plugin | プラグインインターフェース   | -            | ✅   |
| provenix-sbom   | SBOM 生成                    | pxb          | ✅   |
| provenix-attest | アテステーション             | pxa          | ✅   |
| provenix-sign   | 署名                         | -            | ✅   |
| provenix-verify | 検証                         | -            | ✅   |
| provenix-cli    | 統合 CLI                     | provenix-cli | ✅   |
| server          | API サーバー                 | pxs          | ✅   |

---

## 🎯 よく使うコマンド

### ビルド

```bash
# 全体ビルド
cargo build --workspace

# リリースビルド
cargo build --workspace --release

# 特定のクレート
cargo build -p provenix-cli
cargo build -p provenix-server
```

### テスト

```bash
# 全テスト
cargo test --workspace

# コアのみ
cargo test -p provenix-core

# 詳細出力
cargo test --workspace -- --nocapture
```

### 実行

```bash
# CLI実行
cargo run -p provenix-cli -- sbom
cargo run -p provenix-cli -- attest

# サーバー起動
cargo run -p provenix-server

# リリース版実行
./target/release/provenix-cli run
./target/release/pxs
```

---

## 🔌 プラグイン開発

### 1. トレイト実装

```rust
use provenix_plugin::SbomProvider;
use serde_json::json;

pub struct MyProvider;

impl SbomProvider for MyProvider {
    fn name(&self) -> &str {
        "my-provider"
    }

    fn generate(&self, target: &str, output: &PathBuf) -> anyhow::Result<Value> {
        // 実装
        Ok(json!({"status": "success"}))
    }
}
```

### 2. 自動登録

```rust
#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_sbom("my-provider", MyProvider);
}
```

### 3. Cargo.toml 設定

```toml
[dependencies]
provenix-core = { path = "../provenix-core" }
provenix-plugin = { path = "../provenix-plugin" }
ctor = "0.2"
anyhow = "1.0"
serde_json = "1.0"
```

---

## 🔐 セキュリティチェックリスト

- [ ] 全ての依存関係を確認: `cargo audit`
- [ ] 警告なしでビルド: `cargo clippy`
- [ ] テスト通過: `cargo test`
- [ ] フォーマット済み: `cargo fmt`
- [ ] セキュアな設定ファイル
- [ ] 環境変数で秘密情報管理
- [ ] TLS 通信の設定
- [ ] 適切なロギング

---

## 📊 トラブルシューティング

### ビルドエラー

**問題**: `no matching package found`

```bash
# 解決: ワークスペースメンバーを確認
cat Cargo.toml
```

**問題**: `file not found for module`

```bash
# 解決: モジュールファイルを作成
touch src/missing_module.rs
```

### 実行時エラー

**問題**: `Provider not found`

```bash
# 解決: プロバイダーが登録されているか確認
# ctorが実行されているか確認
```

**問題**: `Lock poisoned`

```bash
# 解決: パニックが発生していないか確認
# ログを確認
RUST_LOG=debug cargo run
```

---

## 🗂️ ファイル構造早見表

```
プロジェクトルート
├── Cargo.toml          ← ワークスペース定義
├── crates/             ← Rustクレート
│   ├── provenix-cli/  ← CLI
│   ├── provenix-core/ ← コア
│   └── provenix-*/    ← その他
├── server/            ← APIサーバー
├── docs/              ← ドキュメント
└── scripts/           ← ビルドスクリプト
```

---

## 🔗 API エンドポイント

| Method | Path                    | 説明                 |
| ------ | ----------------------- | -------------------- |
| GET    | `/health`               | ヘルスチェック       |
| GET    | `/api/v1`               | API 情報             |
| POST   | `/api/v1/auth/login`    | ログイン             |
| GET    | `/api/v1/auth/verify`   | トークン検証         |
| POST   | `/api/v1/sbom/`         | SBOM 作成            |
| GET    | `/api/v1/sbom/`         | SBOM リスト          |
| GET    | `/api/v1/sbom/:id`      | SBOM 取得            |
| POST   | `/api/v1/attest/`       | アテステーション作成 |
| POST   | `/api/v1/attest/verify` | アテステーション検証 |

---

## 💡 ベストプラクティス

### コーディング

✅ エラーは`Result`型で返す  
✅ `unwrap()`は避ける  
✅ ドキュメントコメントを書く  
✅ テストを書く  
✅ `#[allow(dead_code)]`は一時的に

### セキュリティ

✅ 秘密情報は環境変数で  
✅ TLS 通信を使用  
✅ 入力を検証  
✅ ログに秘密情報を出力しない  
✅ 最小権限の原則

### パフォーマンス

✅ `Arc`でクローンを軽量化  
✅ 不要なロックを避ける  
✅ 非同期処理を活用  
✅ データベースクエリを最適化

---

## 🐛 デバッグ Tips

### ログレベル設定

```bash
# 全体をdebugレベルで
RUST_LOG=debug cargo run

# 特定モジュールのみ
RUST_LOG=provenix_core=trace cargo run

# 複数モジュール
RUST_LOG=provenix_core=debug,provenix_cli=info cargo run
```

### バックトレース

```bash
# フルスタックトレース
RUST_BACKTRACE=1 cargo run

# さらに詳細
RUST_BACKTRACE=full cargo run
```

### テストデバッグ

```bash
# 特定のテスト
cargo test test_name -- --nocapture

# 失敗したテストのみ
cargo test --workspace -- --test-threads=1
```

---

## 📚 ドキュメントリンク

- [プロジェクト全体像](PROJECT_OVERVIEW.md) - まずはここから！
- [技術仕様書](TECHNICAL_SPECIFICATION.md) - 詳細な技術情報
- [アーキテクチャ](architecture.md) - システム設計
- [セキュリティモデル](SECURITY_MODEL.md) - セキュリティ設計
- [デプロイメントガイド](DEPLOYMENT_GUIDE.md) - 本番環境構築
- [API 仕様](api.md) - API リファレンス
- [CLI 使用法](cli.md) - コマンドライン操作

---

## 🤝 コントリビューション

```bash
# 1. ブランチ作成
git checkout -b feature/my-feature

# 2. 変更実装
# ... コード編集 ...

# 3. テスト
cargo test --workspace

# 4. フォーマット
cargo fmt --all

# 5. コミット
git add .
git commit -m "Add: my feature"

# 6. プッシュ
git push origin feature/my-feature

# 7. プルリクエスト作成
```

---

## 🆘 ヘルプ

### よくある質問

**Q: ビルドが遅い**  
A: `cargo build --release`は最適化のため時間がかかります。開発時は`cargo build`を使用してください。

**Q: テストが失敗する**  
A: `cargo clean`してから再ビルドしてください。

**Q: プロバイダーが見つからない**  
A: `ctor`クレートが正しく設定されているか確認してください。

**Q: データベース接続エラー**  
A: PostgreSQL が起動しているか、接続文字列が正しいか確認してください。

### サポート

- 🐛 バグ報告: [GitHub Issues](https://github.com/hoso8722/provenix/issues)
- 💬 質問: [GitHub Discussions](https://github.com/hoso8722/provenix/discussions)
- 🔒 セキュリティ: security@provenix.dev

---

## 📅 バージョン履歴

### v0.1.0 (2025-11-18)

- ✅ 初期アーキテクチャ実装
- ✅ コアレジストリシステム
- ✅ 基本プロバイダー実装
- ✅ CLI・サーバー基盤

---

**最終更新**: 2025 年 11 月 18 日  
**対象バージョン**: 0.1.0
