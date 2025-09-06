# SSLcat - SSL プロキシサーバー

## ⏱️ SSLcat 1分間クイックスタート

```bash
# 1) ワンクリックインストール（Linux）
# 中国本土ユーザー向け（sslcat.com経由で高速化）
curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.0.11
# 本土以外のユーザーはGitHub rawコンテンツを直接使用可能：
# curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.0.11

# 2) macOS ローカル クイックテスト（またはdarwinパッケージを手動ダウンロード）
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.0.12/sslcat_1.0.12_darwin_arm64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat
sslcat --config sslcat.conf --port 8080
# ブラウザアクセス: http://localhost:8080/sslcat-panel/
# 初回ログイン：admin / admin*9527（パスワード変更を強制され、admin.passを生成）

# 3) オプション：Docker Compose ワンクリック起動
docker compose up -d
```

SSLcat は、自動証明書管理、ドメイン転送、セキュリティ保護、Web管理パネルをサポートする強力なSSLプロキシサーバーです。HTTP/3 (QUIC) とHTTP/2プロトコルサポート（自動ネゴシエーション、下位互換）も提供します。

## 📚 ドキュメントナビゲーション

- 📑 [完全ドキュメントインデックス](DOCS.md) - すべてのドキュメントのインデックスとナビゲーション
- 📖 [プロジェクト概要](项目总结.md) - 詳細な機能紹介と技術文書
- 🚀 [デプロイガイド（中国語）](DEPLOYMENT.md) - 完全なデプロイと運用文書
- 🚀 [デプロイガイド（英語）](DEPLOYMENT_EN.md) - 英語デプロイガイド

### 🌍 多言語版
- 🇨🇳 [中文 README](README.md) - 中国語版
- 🇺🇸 [English README](README_EN.md) - 英語版
- 🇪🇸 [Español README](README_ES.md) - スペイン語版
- 🇫🇷 [Français README](README_FR.md) - フランス語版
- 🇷🇺 [Русский README](README_RU.md) - ロシア語版

## 機能

### 🌏 中国向けネットワーク最適化
- **CDN プロキシ最適化**: [CDNProxy](https://cdnproxy.some.im/docs) プロキシサービスを使用
- **アクセス高速化**: 中国本土でのjsdelivr CDNアクセス問題を解決
- **安定性**: プロキシサービスによる安定したリソース読み込みを保証

### 🔒 自動SSL証明書管理
- Let's Encrypt からSSL証明書を自動取得
- 証明書の自動更新をサポート
- ステージング環境と本番環境をサポート
- 証明書キャッシュとパフォーマンス最適化
- **バッチ証明書操作**: すべての証明書のワンクリックダウンロード/インポート（ZIP形式）

### 🔄 スマートドメイン転送
- ドメイン名ベースのインテリジェントプロキシ転送
- HTTP/HTTPSプロトコルをサポート
- WebSocketプロキシをサポート
- コネクションプーリングとロードバランシング

### 🛡️ セキュリティ保護メカニズム
- IPブロックとアクセス制御
- ブルートフォース攻撃対策
- User-Agent検証
- アクセスログ記録
- **TLSクライアントフィンガープリンティング**: ClientHello特性によるクライアント識別
- **本番環境最適化**: 高トラフィックシナリオのためのより寛容なセキュリティ閾値

### 🎛️ Web管理パネル
- 直感的なWebインターフェース
- リアルタイム監視と統計
- プロキシルール管理
- SSL証明書管理
- セキュリティ設定
- **APIトークン管理**: 読み取り専用/読み書きAPIアクセス制御
- **TLSフィンガープリント統計**: リアルタイムクライアントフィンガープリント分析データ

### 🔄 グレースフル再起動
- ゼロダウンタイム再起動
- コネクション保持と状態復旧
- グレースフルシャットダウンメカニズム

## システム要件

- Linuxシステム（Ubuntu/Debian/CentOS/RHEL）
- Go 1.21以上
- root権限
- ポート80と443が利用可能

## 📥 ソースコード取得

### GitHubリポジトリ

プロジェクトはGitHubでホスト: **[https://github.com/xurenlu/sslcat](https://github.com/xurenlu/sslcat)**

### 最新版ダウンロード

```bash
# 最新ソースコードをクローン
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# または特定バージョンをダウンロード（推奨）
wget https://github.com/xurenlu/sslcat/archive/refs/heads/main.zip
unzip main.zip
cd sslcat-main
```

## 🚀 インストールとデプロイ

### 手動インストール

1. **依存関係のインストール**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y curl wget git build-essential ca-certificates certbot

# CentOS/RHEL
sudo yum update -y
sudo yum install -y curl wget git gcc gcc-c++ make ca-certificates certbot
```

2. **Goのインストール**
```bash
# Go 1.21をダウンロード・インストール
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

3. **SSLcatのコンパイル**
```bash
git clone https://github.com/xurenlu/sslcat.git
cd sslcat
go mod download
go build -o sslcat main.go
```

4. **ユーザーとディレクトリの作成**
```bash
sudo useradd -r -s /bin/false sslcat
sudo mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs}
sudo chown -R sslcat:sslcat /var/lib/sslcat
```

5. **設定と起動**
```bash
sudo cp sslcat /opt/sslcat/
sudo cp sslcat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sslcat
sudo systemctl start sslcat
```

## 設定

### 設定ファイルの場所
- メイン設定ファイル: `/etc/sslcat/sslcat.conf`
- 証明書ディレクトリ: `/var/lib/sslcat/certs`
- キーディレクトリ: `/var/lib/sslcat/keys`
- ログディレクトリ: `/var/lib/sslcat/logs`

### 基本設定

```yaml
server:
  host: "0.0.0.0"
  port: 443
  debug: false

ssl:
  email: "your-email@example.com"  # SSL証明書メール
  staging: false                   # ステージング環境を使用するか
  auto_renew: true                 # 自動更新

admin:
  username: "admin"
  password_file: "/var/lib/sslcat/admin.pass"     # パスワードはこのファイルに保存、sslcat.confはpasswordを永続化しない
  first_run: true

proxy:
  rules:
    - domain: "example.com"
      target: "127.0.0.1"
      port: 8080
      enabled: true
      ssl_only: true

security:
  max_attempts: 3                  # 1分間の最大失敗回数
  block_duration: "1m"             # ブロック期間
  max_attempts_5min: 10            # 5分間の最大失敗回数

admin_prefix: "/sslcat-panel"     # 管理パネルパスプレフィックス
```

### パスワード復旧（緊急復旧）

SSLcatは「マーカーファイル + 初回強制パスワード変更」セキュリティ戦略を採用：

- マーカーファイル: `admin.password_file`（デフォルト `./data/admin.pass`）。ファイルは0600権限で現在の管理者パスワードを保存。
- 初回ログイン: マーカーファイルが存在しない、またはファイル内容がデフォルトパスワード `admin*9527` のままの場合、管理者ログイン成功後「パスワード変更」ページに強制移動し、新パスワードを設定してマーカーファイルに書き込み。

パスワード復旧手順:

1. サービス停止（または稼働継続可、停止推奨）。
2. マーカーファイルを削除（パスが変更されている場合は、実際の設定パスに従って削除）：
   ```bash
   rm -f ./data/admin.pass
   ```
3. サービス再起動、デフォルトアカウントでログイン（admin / admin*9527）。
4. システムが強制的に「パスワード変更」ページに移動、新パスワード設定後正常動作復旧。

注意：セキュリティ上の理由により、`sslcat.conf`は保存時に `admin.password` 平文を永続化しなくなりました；実行時の実際のパスワードは `admin.password_file` を基準とします。

## 使用方法

### サービス開始
```bash
sudo systemctl start sslcat
```

### サービス停止
```bash
sudo systemctl stop sslcat
```

### サービス再起動
```bash
sudo systemctl restart sslcat
```

### グレースフル再起動
```bash
sudo systemctl reload sslcat
# またはSIGHUPシグナル送信
sudo kill -HUP $(pgrep sslcat)
```

### ログ表示
```bash
# サービス状態を表示
sudo systemctl status sslcat

# リアルタイムログを表示
sudo journalctl -u sslcat -f

# エラーログを表示
sudo journalctl -u sslcat -p err
```

## Web管理パネル

### 管理パネルへのアクセス

**⚠️ 重要：初期アクセス方法**

システムを初めてインストールした時はSSL証明書がないため、初期アクセスには以下の方法を使用してください：

1. **初回アクセス**（サーバーIPアドレスを使用）：
   ```
   http://YOUR_SERVER_IP/sslcat-panel
   ```
   注意：`http://`（httpsではない）を使用、SSL証明書がまだないため

2. **ドメイン設定と証明書取得後**：
   ```
   https://your-domain/your-custom-panel-path
   ```

**ログインプロセス：**
1. デフォルト認証情報でログイン:
   - ユーザー名: `admin`
   - パスワード: `admin*9527`
2. 初回ログインで強制：
   - 管理者パスワードの変更
   - 管理パネルアクセスパスのカスタマイズ（セキュリティのため）
3. **新しい管理パネルパスを必ず記憶してください！**システムが自動で新しいパスにリダイレクトします

### 管理パネル機能
- **ダッシュボード**: システム状態と統計を表示
- **プロキシ設定**: ドメイン転送ルール管理
- **SSL証明書**: SSL証明書の表示と管理
- **セキュリティ設定**: セキュリティポリシー設定とブロックIP表示
- **システム設定**: システム設定の変更

## プロキシ設定

### プロキシルールの追加
1. 管理パネルにログイン
2. 「プロキシ設定」ページに移動
3. 「新規プロキシルール」をクリック
4. 設定を入力:
   - ドメイン: プロキシするドメイン
   - ターゲット: バックエンドサーバーのIPまたはドメイン
   - ポート: バックエンドサービスポート
   - 有効: このルールを有効にするか
   - SSL のみ: HTTPSアクセスのみ許可するか

### プロキシルール例
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "127.0.0.1"
      port: 3000
      enabled: true
      ssl_only: true
    - domain: "app.example.com"
      target: "192.168.1.100"
      port: 8080
      enabled: true
      ssl_only: false
```

## SSL証明書管理

### 自動証明書取得
SSLcatは設定されたドメインのSSL証明書を手動介入なしに自動取得します。

### 証明書更新
証明書は期限切れの30日前に自動更新、または手動でトリガー可能。

### 証明書保存
- 証明書ファイル: `/var/lib/sslcat/certs/domain.crt`
- 秘密鍵ファイル: `/var/lib/sslcat/keys/domain.key`

## セキュリティ機能

### IPブロックメカニズム
- 1分間に3回失敗後自動ブロック
- 5分間に10回失敗後自動ブロック
- ブロック期間は設定可能
- 手動ブロック解除をサポート

### アクセス制御
- User-Agent検証
- 空のUser-Agentアクセスを拒否
- 一般的でないブラウザUser-Agentアクセスを拒否

### IPブロック解除
```bash
# ブロックファイルを削除してサービス再起動
sudo rm /var/lib/sslcat/sslcat.block
sudo systemctl restart sslcat
```

## コマンドライン引数

```bash
sslcat [オプション]

オプション:
  --config string        設定ファイルパス（デフォルト: "/etc/sslcat/sslcat.conf"）
  --admin-prefix string  管理パネルパスプレフィックス（デフォルト: "/sslcat-panel"）
  --email string         SSL証明書メール
  --staging             Let's Encryptステージング環境を使用
  --port int            リスンポート（デフォルト: 443）
  --host string         リスンアドレス（デフォルト: "0.0.0.0"）
  --log-level string    ログレベル（デフォルト: "info"）
  --version             バージョン情報を表示
```

## トラブルシューティング

### よくある問題

1. **サービス起動失敗**
   ```bash
   # 設定ファイル構文チェック
   sudo withssl --config /etc/sslcat/withssl.conf --log-level debug
   
   # ポート使用状況チェック
   sudo netstat -tlnp | grep :443
   ```

2. **SSL証明書取得失敗**
   - ドメイン解決が正しいことを確認
   - ポート80がアクセス可能であることを確認
   - ファイアウォール設定をチェック
   - テスト用にステージング環境を使用

3. **プロキシ転送失敗**
   - ターゲットサーバーに到達可能かチェック
   - ポートが正しいか確認
   - アクセスログをチェック

4. **管理パネルアクセス不可**
   - ファイアウォール設定をチェック
   - SSL証明書が有効か確認
   - サービスログをチェック

### ログ分析
```bash
# 詳細ログを表示
sudo journalctl -u sslcat -f --no-pager

# エラーログをフィルタ
sudo journalctl -u sslcat -p err --since "1 hour ago"

# 特定時間帯のログを表示
sudo journalctl -u sslcat --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
```

## パフォーマンス最適化

### システム最適化
```bash
# ファイルディスクリプタ制限を増加
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# ネットワークパラメータを最適化
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### 設定最適化
```yaml
server:
  # パフォーマンス分析用にデバッグモードを有効化
  debug: false
  
proxy:
  # 適切なプロキシルール数を設定
  rules: []
  
security:
  # セキュリティパラメータを調整
  max_attempts: 5
  block_duration: "5m"
```

## ネットワーク最適化

### 中国本土ユーザー最適化

SSLcatプロジェクトは中国本土ネットワーク環境向けに最適化され、[CDNProxy](https://cdnproxy.some.im/docs) プロキシサービスを使用してjsdelivr CDNアクセス問題を解決しています。

#### CDNプロキシ使用
- **元のアドレス**: `https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`
- **プロキシアドレス**: `https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`

#### 関係するリソースファイル
- Bootstrap 5.1.3 CSS
- Bootstrap Icons 1.7.2
- Bootstrap 5.1.3 JavaScript
- Axios JavaScriptライブラリ

#### アクセス制御
CDNProxyドキュメントによると、このサービスはアクセス制御ポリシーを実装しています。アクセスがブロックされる場合、通常はリクエストのRefererドメインがホワイトリストにないためです。必要に応じて、サービス管理者に連絡してドメインをホワイトリストに追加してください。

## 開発ガイド

### プロジェクト構造
```
sslcat/
├── main.go                 # メインプログラムエントリ
├── go.mod                  # Goモジュールファイル
├── internal/               # 内部パッケージ
│   ├── config/            # 設定管理
│   ├── logger/            # ログ管理
│   ├── ssl/               # SSL証明書管理
│   ├── proxy/             # プロキシ管理
│   ├── security/          # セキュリティ管理
│   ├── web/               # Webサーバー
│   └── graceful/          # グレースフル再起動
├── web/                   # Webリソース
│   ├── templates/         # HTMLテンプレート
│   └── static/            # 静的リソース
├── install.sh             # インストールスクリプト
└── README.md              # ドキュメント
```

### 開発環境セットアップ
```bash
# プロジェクトをクローン
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# 依存関係をインストール
go mod download

# 開発サーバーを実行
go run main.go --config sslcat.conf --log-level debug
```

### 貢献ガイド
1. プロジェクトをFork
2. 機能ブランチを作成
3. 変更をコミット
4. ブランチにプッシュ
5. Pull Requestを作成

## ライセンス

このプロジェクトはMITライセンスを使用しています。詳細は [LICENSE](LICENSE) ファイルを参照してください。

## サポート

問題が発生した場合や提案がある場合:
1. [トラブルシューティング](#トラブルシューティング) セクションをチェック
2. [Issues](https://github.com/xurenlu/sslcat/issues) を検索
3. 新しいIssueを作成
4. メンテナーに連絡

## 変更履歴

完全なバージョン更新履歴はこちらを参照してください：**[CHANGELOG.md](CHANGELOG.md)**

### 最新バージョン v1.0.13 (2025-01-03)
- 🌐 Master-Slaveクラスターアーキテクチャ：高可用性のためのマルチノードデプロイメントサポート
- 🔄 自動設定同期：MasterからすべてのSlaveノードへのリアルタイム設定プッシュ
- 🔒 権限分離制御：Slaveモードでの厳格な機能制限
- 🖥️ クラスター管理インターフェース：完全なノード状態監視と管理
- 📊 詳細監視情報：IPアドレス、ポート、証明書数、設定MD5など包括的な情報