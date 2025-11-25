# Provenix 技術仕様書

## 📐 システムアーキテクチャ詳細

### レイヤー構成

```
┌───────────────────────────────────────────────────────────────┐
│                        プレゼンテーション層                    │
├───────────────────────────────────────────────────────────────┤
│  CLI (provenix-cli)  │  Web UI (React)  │  API Clients       │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                        アプリケーション層                       │
├───────────────────────────────────────────────────────────────┤
│  Server (pxs)                                                 │
│  ├─ Routes (APIエンドポイント)                                │
│  ├─ Auth (認証・認可)                                         │
│  ├─ Policy (OPAポリシー評価)                                 │
│  └─ Services (ビジネスロジック)                               │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                          ドメイン層                            │
├───────────────────────────────────────────────────────────────┤
│  provenix-core                                                │
│  ├─ Registry (プロバイダー管理)                               │
│  ├─ Pipeline (ワークフロー調整)                               │
│  └─ Config (設定管理)                                         │
│                                                               │
│  provenix-plugin                                              │
│  └─ Traits (インターフェース定義)                             │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                      インフラストラクチャ層                     │
├───────────────────────────────────────────────────────────────┤
│  Providers                                                    │
│  ├─ provenix-sbom (Syft)                                     │
│  ├─ provenix-attest (In-Toto)                                │
│  ├─ provenix-sign (Cosign)                                   │
│  └─ provenix-verify (Sigstore)                               │
│                                                               │
│  Storage                                                      │
│  └─ PostgreSQL (SQLx)                                        │
│                                                               │
│  External Tools                                               │
│  └─ Syft, Cosign, Sigstore CLI                              │
└───────────────────────────────────────────────────────────────┘
```

---

## 🔄 データフローの詳細

### 1. SBOM 生成フロー

```
┌────────────┐
│   ユーザー  │
└─────┬──────┘
      │ provenix sbom
      ▼
┌──────────────────┐
│ provenix-cli     │
│ executor/sbom.rs │
└─────┬────────────┘
      │ get_sbom("syft")?
      ▼
┌──────────────────┐
│ provenix-core    │
│ registry         │
└─────┬────────────┘
      │ Arc<dyn SbomProvider>
      ▼
┌──────────────────┐
│ provenix-sbom    │
│ SyftProvider     │
└─────┬────────────┘
      │ 外部コマンド実行
      ▼
┌──────────────────┐
│   syft CLI       │
│   実行           │
└─────┬────────────┘
      │ JSON出力
      ▼
┌──────────────────┐
│   sbom.json      │
│   ファイル保存    │
└──────────────────┘
```

### 2. アテステーションフロー

```
┌────────────┐
│   ユーザー  │
└─────┬──────┘
      │ provenix attest
      ▼
┌──────────────────┐
│ provenix-cli     │
│ executor/        │
│ attest.rs        │
└─────┬────────────┘
      │
      ▼
┌──────────────────┐
│ provenix-core    │
│ get_attest()     │
└─────┬────────────┘
      │
      ▼
┌──────────────────┐
│ provenix-attest  │
│ InTotoProvider   │
└─────┬────────────┘
      │
      ▼
┌──────────────────┐
│ SBOM読み込み      │
│ メタデータ付加    │
└─────┬────────────┘
      │
      ▼
┌──────────────────┐
│ attestation.json │
│ 生成             │
└──────────────────┘
```

### 3. 署名・検証フロー

```
署名フロー:
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ artifact │ -> │ sign()   │ -> │ Cosign   │ -> │.sig file │
└──────────┘    └──────────┘    └──────────┘    └──────────┘

検証フロー:
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ artifact │ -> │ verify() │ -> │Sigstore  │ -> │ Result   │
│.sig file │    │          │    │          │    │ Valid?   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

### 4. API サーバーフロー

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP Request
       ▼
┌─────────────────────┐
│ Axum Router         │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Middleware Stack    │
│ ├─ TraceLayer       │
│ ├─ CorsLayer        │
│ └─ AuthLayer (TODO) │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Route Handler       │
│ (routes/sbom.rs)    │
└──────┬──────────────┘
       │
       ├─────────────────┐
       ▼                 ▼
┌──────────────┐  ┌──────────────┐
│ Auth Check   │  │ Policy Check │
│ (auth/mod.rs)│  │(policy/mod.rs│
└──────┬───────┘  └──────┬───────┘
       │                 │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │ Service Layer   │
       │(services/mod.rs)│
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │ Storage Layer   │
       │(storage/mod.rs) │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │  PostgreSQL     │
       └─────────────────┘
```

---

## 🗄️ データモデル

### データベーススキーマ

#### SBOMs テーブル

```sql
CREATE TABLE sboms (
    id UUID PRIMARY KEY,
    project VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    format VARCHAR(50) NOT NULL,     -- 'spdx', 'cyclonedx', etc.
    data JSONB NOT NULL,
    hash VARCHAR(255) NOT NULL,      -- SHA256ハッシュ
    created_at TIMESTAMP NOT NULL,
    created_by VARCHAR(255) NOT NULL,

    INDEX idx_project (project),
    INDEX idx_created_at (created_at)
);
```

#### Attestations テーブル

```sql
CREATE TABLE attestations (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,        -- SBOMまたは成果物のID
    attestation_type VARCHAR(50) NOT NULL,
    signature TEXT NOT NULL,
    certificate TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    verifier VARCHAR(255) NOT NULL,

    FOREIGN KEY (subject_id) REFERENCES sboms(id),
    INDEX idx_subject_id (subject_id),
    INDEX idx_timestamp (timestamp)
);
```

### JSON データ構造

#### SBOM (SPDX 形式例)

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-project",
  "documentNamespace": "https://example.com/my-project",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-1",
      "name": "package-name",
      "versionInfo": "1.0.0",
      "filesAnalyzed": false
    }
  ]
}
```

#### Attestation (In-Toto 形式例)

```json
{
  "_type": "link",
  "name": "build",
  "materials": {
    "sbom.json": {
      "sha256": "abc123..."
    }
  },
  "products": {
    "binary": {
      "sha256": "def456..."
    }
  },
  "command": ["cargo", "build", "--release"],
  "byproducts": {},
  "environment": {}
}
```

---

## 🔌 プラグインシステム詳細

### プロバイダーライフサイクル

```
1. 定義
   ↓
   pub struct MyProvider;

2. トレイト実装
   ↓
   impl SbomProvider for MyProvider {
       fn name(&self) -> &str { "my" }
       fn generate(...) -> Result<Value> { ... }
   }

3. 自動登録
   ↓
   #[ctor::ctor]
   fn register() {
       register_sbom("my", MyProvider);
   }

4. 実行時取得
   ↓
   let provider = get_sbom("my")?;

5. 実行
   ↓
   provider.generate(target, output)?;
```

### レジストリ内部構造

```rust
// グローバルレジストリ
static SBOM_REGISTRY: Lazy<RwLock<HashMap<String, Arc<dyn SbomProvider>>>>

// 構造
SBOM_REGISTRY = {
    "syft" -> Arc(SyftProvider),
    "custom" -> Arc(CustomProvider),
    ...
}

// アクセスパターン
読み取り: RwLock::read()  -> 複数スレッド同時可能
書き込み: RwLock::write() -> 排他的アクセス

// クローン
Arc::clone() -> 参照カウントのみ増加（軽量）
```

---

## 🔐 セキュリティアーキテクチャ

### 認証フロー

```
1. ユーザーログイン
   ┌──────────┐
   │  Client  │
   └────┬─────┘
        │ POST /api/v1/auth/login
        ▼
   ┌──────────────┐
   │ Auth Service │
   └────┬─────────┘
        │ OIDC Redirect
        ▼
   ┌──────────────┐
   │ OIDC Provider│
   │ (Auth0, etc) │
   └────┬─────────┘
        │ ID Token
        ▼
   ┌──────────────┐
   │ Token Verify │
   └────┬─────────┘
        │ JWT + Claims
        ▼
   ┌──────────────┐
   │   Client     │
   └──────────────┘

2. API呼び出し
   ┌──────────┐
   │  Client  │
   │ + JWT    │
   └────┬─────┘
        │ Authorization: Bearer <token>
        ▼
   ┌──────────────┐
   │ Auth Middle  │
   │ ware         │
   └────┬─────────┘
        │ Validate JWT
        │ Extract Claims
        ▼
   ┌──────────────┐
   │ Policy Check │
   │ (OPA)        │
   └────┬─────────┘
        │ Allow/Deny
        ▼
   ┌──────────────┐
   │ API Handler  │
   └──────────────┘
```

### ポリシー評価

```
Request Context:
{
  "subject": "user@example.com",
  "action": "POST",
  "resource": "/api/v1/sbom",
  "context": {
    "roles": ["developer"],
    "permissions": ["sbom:write"],
    "timestamp": 1234567890
  }
}

       ↓ 送信

┌─────────────────┐
│  OPA Engine     │
│  rego policy    │
└────────┬────────┘
         │
         ▼
Decision:
{
  "allow": true,
  "reason": "User has sbom:write permission",
  "obligations": []
}
```

---

## 📊 パフォーマンス考慮事項

### レジストリアクセス

| 操作     | 時間計算量 | 備考                        |
| -------- | ---------- | --------------------------- |
| register | O(1)       | HashMap insert              |
| get      | O(1)       | HashMap lookup + Arc::clone |
| list     | O(n)       | 全キーの走査                |
| has      | O(1)       | HashMap contains_key        |

### 同時実行性

```
読み取り（複数可）:
┌──────┐  ┌──────┐  ┌──────┐
│Thread│  │Thread│  │Thread│
│  1   │  │  2   │  │  3   │
└──┬───┘  └──┬───┘  └──┬───┘
   │         │         │
   └─────────┴─────────┘
             ▼
   ┌──────────────────┐
   │ RwLock::read()   │
   │ 同時アクセス可   │
   └──────────────────┘

書き込み（排他）:
┌──────┐  ┌──────┐  ┌──────┐
│Thread│  │Thread│  │Thread│
│  1   │  │  2   │  │  3   │
└──┬───┘  └──┬───┘  └──┬───┘
   │ ✓       │ ⏸️      │ ⏸️
   ▼         │         │
┌──────────────────┐  │
│ RwLock::write()  │  │
│ 排他アクセス     │  │
└──────────────────┘  │
         └────────────┘
```

---

## 🧪 テスト戦略

### テストピラミッド

```
       /\
      /  \
     / E2E \         ← 少数の統合テスト
    /──────\
   / API    \       ← 中程度のAPIテスト
  /──────────\
 /  Unit      \     ← 多数の単体テスト
/──────────────\
```

### テストカバレッジ

| コンポーネント  | ユニット   | 統合 | E2E | 状態 |
| --------------- | ---------- | ---- | --- | ---- |
| provenix-core   | ✅ 4 tests | -    | -   | 完了 |
| provenix-plugin | 🚧         | -    | -   | TODO |
| provenix-sbom   | 🚧         | -    | -   | TODO |
| provenix-attest | 🚧         | -    | -   | TODO |
| provenix-cli    | 🚧         | 🚧   | -   | TODO |
| server          | 🚧         | 🚧   | 🚧  | TODO |

---

## 🚀 デプロイメント

### コンテナ構成

```
Docker Compose:
┌─────────────────────────────────────────┐
│                                         │
│  ┌──────────────┐  ┌──────────────┐   │
│  │ provenix-cli │  │provenix-server│   │
│  │  Container   │  │   Container  │   │
│  └──────────────┘  └───────┬──────┘   │
│                            │           │
│                            ▼           │
│                    ┌──────────────┐   │
│                    │  PostgreSQL  │   │
│                    │   Container  │   │
│                    └──────────────┘   │
│                                        │
└────────────────────────────────────────┘
```

### Kubernetes 構成（計画）

```
┌────────────────────────────────────────┐
│           Ingress                      │
│  (TLS Termination, Load Balancing)    │
└───────────────┬────────────────────────┘
                ▼
┌────────────────────────────────────────┐
│     Service (provenix-server)         │
└───────────────┬────────────────────────┘
                ▼
┌──────────────────────────────────────────┐
│         Deployment                       │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│  │  Pod 1  │  │  Pod 2  │  │  Pod 3  │ │
│  │ Server  │  │ Server  │  │ Server  │ │
│  └─────────┘  └─────────┘  └─────────┘ │
└──────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────┐
│      StatefulSet (PostgreSQL)            │
│  ┌─────────┐                             │
│  │Primary  │──replication──┐             │
│  └─────────┘               ▼             │
│                      ┌─────────┐         │
│                      │Replica  │         │
│                      └─────────┘         │
└──────────────────────────────────────────┘
```

---

## 📈 ロードマップ

### Phase 1: 基盤構築 (現在)

- ✅ コアアーキテクチャ
- ✅ レジストリシステム
- ✅ 基本プロバイダー
- ✅ CLI フレームワーク
- ✅ API サーバー基盤

### Phase 2: 機能拡充

- 🚧 Web フロントエンド
- 🚧 脆弱性スキャン
- 🚧 レポート生成
- 📋 CI/CD 統合

### Phase 3: エンタープライズ機能

- 📋 マルチテナント
- 📋 高可用性構成
- 📋 監視・アラート
- 📋 コンプライアンスレポート

### Phase 4: 高度な機能

- 📋 機械学習による異常検知
- 📋 自動修復提案
- 📋 ブロックチェーン統合
- 📋 量子耐性暗号

---

## 🔗 外部連携

### 統合予定のツール

| ツール             | 用途               | 優先度 |
| ------------------ | ------------------ | ------ |
| **GitHub Actions** | CI/CD 統合         | 高     |
| **GitLab CI**      | CI/CD 統合         | 中     |
| **Jenkins**        | CI/CD 統合         | 中     |
| **Harbor**         | コンテナレジストリ | 高     |
| **Artifactory**    | 成果物管理         | 中     |
| **Grafana**        | 監視・可視化       | 高     |
| **Prometheus**     | メトリクス収集     | 高     |
| **Vault**          | シークレット管理   | 高     |

---

## 📝 設定ファイル例

### provenix.yaml

```yaml
sbom:
  provider: "syft"
  target: "."
  output: "sbom.json"

attest:
  provider: "in-toto"
  sbom_path: "sbom.json"
  output: "attestation.json"

sign:
  provider: "cosign"
  artifact_path: "binary"
  key_path: "key.pem"
  output: "signature.sig"

verify:
  provider: "sigstore"
  artifact_path: "binary"
  signature_path: "signature.sig"

publish:
  registry_url: "https://registry.example.com"
```

### server config (default.toml)

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "postgresql://localhost/provenix"
max_connections = 20

[auth]
jwt_secret = "${JWT_SECRET}"
oidc_issuer_url = "${OIDC_ISSUER_URL}"
oidc_client_id = "${OIDC_CLIENT_ID}"

[policy]
opa_url = "http://localhost:8181"
```

---

## 🎓 学習リソース

### 推奨ドキュメント

- [SLSA Framework](https://slsa.dev/)
- [in-toto Specification](https://github.com/in-toto/docs)
- [SPDX Specification](https://spdx.dev/)
- [CycloneDX](https://cyclonedx.org/)
- [Sigstore Documentation](https://docs.sigstore.dev/)

### コード例リポジトリ

- [Syft](https://github.com/anchore/syft)
- [Cosign](https://github.com/sigstore/cosign)
- [in-toto Golang](https://github.com/in-toto/in-toto-golang)

---

**作成日**: 2025 年 11 月 18 日  
**バージョン**: 0.1.0  
**メンテナー**: Provenix Team
