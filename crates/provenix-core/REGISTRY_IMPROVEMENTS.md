# Registry Implementation - 改善版実装ガイド

## 📝 実装した改善点

### 1. ✅ エラーハンドリングの追加

#### Before (問題あり)

```rust
pub fn register_sbom(name: &'static str, prov: Box<dyn SbomProvider>) {
    SBOM_REGISTRY.write().unwrap().insert(name, prov); // パニックする可能性
}
```

#### After (改善版)

```rust
pub fn register_sbom<P: SbomProvider + 'static>(name: impl Into<String>, provider: P) -> Result<()> {
    let name = name.into();
    let mut registry = SBOM_REGISTRY
        .write()
        .map_err(|e| RegistryError::from(e))?; // エラーを適切に処理

    if registry.contains_key(&name) {
        bail!(RegistryError::ProviderAlreadyExists(name)); // 重複チェック
    }

    registry.insert(name, Arc::new(provider));
    Ok(())
}
```

**改善内容:**

- `unwrap()` → `map_err()` でエラーを返す
- 重複登録のチェックを追加
- `Result<()>` で呼び出し元がエラーハンドリング可能

---

### 2. ✅ Arc<T>によるクローン不要の効率化

#### Before

```rust
Box<dyn SbomProvider> // box_clone()メソッドが必要
```

#### After

```rust
Arc<dyn SbomProvider> // Arc::clone()で参照カウントのみ増加
```

**改善内容:**

- `Arc`により効率的なクローン（参照カウントのみ）
- `box_clone()`トレイトメソッドが不要
- メモリコピーなしで共有可能

---

### 3. ✅ 'static ライフタイムの制約を除去

#### Before

```rust
pub fn register_sbom(name: &'static str, ...) // 静的文字列のみ
```

#### After

```rust
pub fn register_sbom<P: SbomProvider + 'static>(name: impl Into<String>, ...)
// 任意の文字列を受け入れる
```

**改善内容:**

- 動的に生成された文字列も登録可能
- より柔軟な API

---

### 4. ✅ カスタムエラー型の追加

```rust
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Provider '{0}' not found")]
    ProviderNotFound(String),

    #[error("Provider '{0}' already registered")]
    ProviderAlreadyExists(String),
}
```

**メリット:**

- エラーの種類が明確
- エラーメッセージが具体的
- エラーハンドリングが容易

---

### 5. ✅ 追加のユーティリティ関数

```rust
// プロバイダー一覧を取得
pub fn list_sbom_providers() -> Result<Vec<String>>

// プロバイダーの存在確認
pub fn has_sbom_provider(name: &str) -> Result<bool>
```

**用途:**

- UI/CLI での選択肢表示
- 条件分岐での存在確認

---

### 6. ✅ 複数のプロバイダータイプをサポート

```rust
// SBOM
register_sbom(), get_sbom(), list_sbom_providers()

// Attestation
register_attest(), get_attest(), list_attest_providers()

// Signing
register_sign(), get_sign(), list_sign_providers()

// Verification
register_verify(), get_verify(), list_verify_providers()
```

---

### 7. ✅ ユニットテストの追加

```rust
#[test]
fn test_register_and_get() { ... }

#[test]
fn test_duplicate_registration() { ... }

#[test]
fn test_provider_not_found() { ... }

#[test]
fn test_list_providers() { ... }
```

---

## 🚀 使用例

### 基本的な使用方法

```rust
use provenix_core::*;
use anyhow::Result;

// プロバイダーの登録
fn setup_providers() -> Result<()> {
    // SBOM プロバイダー
    register_sbom("syft", SyftProvider::new())?;
    register_sbom("cyclonedx", CycloneDxProvider::new())?;

    // Attest プロバイダー
    register_attest("in-toto", InTotoProvider::new())?;

    // Sign プロバイダー
    register_sign("cosign", CosignProvider::new())?;

    // Verify プロバイダー
    register_verify("sigstore", SigstoreProvider::new())?;

    Ok(())
}

// プロバイダーの使用
fn generate_sbom(target: &str) -> Result<()> {
    // プロバイダーを取得
    let provider = get_sbom("syft")?;

    // SBOMを生成
    let output = PathBuf::from("sbom.json");
    provider.generate(target, &output)?;

    Ok(())
}

// エラーハンドリング
fn safe_register() -> Result<()> {
    match register_sbom("duplicate", MyProvider::new()) {
        Ok(_) => println!("Registered successfully"),
        Err(e) => {
            eprintln!("Registration failed: {}", e);
            // 適切な回復処理
        }
    }
    Ok(())
}

// 利用可能なプロバイダーのリスト
fn list_available() -> Result<()> {
    let providers = list_sbom_providers()?;
    println!("Available SBOM providers:");
    for name in providers {
        println!("  - {}", name);
    }
    Ok(())
}

// 条件付き登録
fn conditional_register() -> Result<()> {
    if !has_sbom_provider("syft")? {
        register_sbom("syft", SyftProvider::new())?;
    }
    Ok(())
}
```

---

## 📊 パフォーマンス比較

| 操作       | Before               | After                    |
| ---------- | -------------------- | ------------------------ |
| 登録       | O(1)                 | O(1) + 重複チェック      |
| 取得       | O(1) + deep クローン | O(1) + Arc::clone (軽量) |
| エラー処理 | パニック             | Result 型で安全          |
| メモリ     | Box 毎にヒープ確保   | Arc 共有参照             |

---

## 🔒 スレッドセーフ性

```rust
// 複数スレッドから安全にアクセス可能
use std::thread;

thread::spawn(|| {
    let provider = get_sbom("syft").unwrap();
    // プロバイダーを使用
});

thread::spawn(|| {
    let provider = get_sbom("syft").unwrap();
    // 同じプロバイダーを別スレッドで使用
});
```

**仕組み:**

- `RwLock`: 複数の読み取り、または単一の書き込み
- `Arc`: スレッド間で安全に共有
- `Send + Sync`: トレイト境界で保証

---

## ⚠️ ベストプラクティス

### ✅ DO (推奨)

```rust
// エラーハンドリング
if let Err(e) = register_sbom("provider", MyProvider) {
    log::error!("Failed to register: {}", e);
    return Err(e);
}

// プロバイダーの存在確認
if has_sbom_provider("syft")? {
    let provider = get_sbom("syft")?;
}

// 早期初期化
fn main() -> Result<()> {
    setup_providers()?;
    // ...
}
```

### ❌ DON'T (非推奨)

```rust
// unwrap()の乱用
register_sbom("provider", MyProvider).unwrap(); // パニックする可能性

// 存在確認なしで取得
let provider = get_sbom("maybe_exists").unwrap();

// エラーの無視
let _ = register_sbom("provider", MyProvider); // エラーを隠蔽
```

---

## 🧪 テスト実行結果

```
running 4 tests
test registry::tests::test_provider_not_found ... ok
test registry::tests::test_duplicate_registration ... ok
test registry::tests::test_list_providers ... ok
test registry::tests::test_register_and_get ... ok

test result: ok. 4 passed; 0 failed; 0 ignored
```

---

## 📦 依存関係

```toml
[dependencies]
anyhow = "1.0"
thiserror = "1.0"
once_cell = "1.19"
provenix-plugin = { path = "../provenix-plugin" }
```

---

## 🎯 まとめ

改善版の実装により以下を達成:

1. ✅ **堅牢性**: エラーハンドリングで予期しないパニックを防止
2. ✅ **効率性**: Arc<T>により軽量なクローン
3. ✅ **柔軟性**: 動的文字列サポート、複数プロバイダータイプ
4. ✅ **使いやすさ**: ユーティリティ関数とわかりやすいエラーメッセージ
5. ✅ **安全性**: スレッドセーフな設計
6. ✅ **品質**: 包括的なユニットテスト

この実装はプロダクション環境で使用可能な品質です！
