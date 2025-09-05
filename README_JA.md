# SSLcat - SSL プロキシサーバー

SSLcat は、自動証明書管理、ドメイン転送、セキュリティ保護、Web管理パネルをサポートする強力なSSLプロキシサーバーです。

## 📚 ドキュメント

- 📑 [完全ドキュメントインデックス](DOCS.md) - すべてのドキュメントのインデックスとナビゲーション
- 📖 [プロジェクト概要 (中国語)](项目总结.md) - 詳細な機能紹介と技術文書
- 🚀 [デプロイガイド (英語)](DEPLOYMENT_EN.md) - 完全なデプロイと運用文書
- 🚀 [部署指南 (中文)](DEPLOYMENT.md) - 中国語デプロイガイド
- 🇨🇳 [中文 README](README.md) - このドキュメントの中国語版
- 🇺🇸 [English README](README_EN.md) - このドキュメントの英語版

## 機能

### 🌏 中国向けネットワーク最適化
- **CDN プロキシ最適化**: [CDNProxy](https://cdnproxy.some.im/docs) サービスを使用
- **アクセス高速化**: 中国本土での jsdelivr CDN アクセス問題を解決
- **安定性**: プロキシサービスによる安定したリソース読み込みを保証

### 🔒 自動SSL証明書管理
- Let's Encrypt から SSL 証明書を自動取得
- 証明書の自動更新をサポート
- ステージング環境と本番環境をサポート
- 証明書キャッシュとパフォーマンス最適化

### 🔄 スマートドメイン転送
- ドメイン名ベースのインテリジェントプロキシ転送
- HTTP/HTTPS プロトコルをサポート
- WebSocket プロキシをサポート
- コネクションプーリングと負荷分散

### 🛡️ セキュリティ保護
- IP ブロックとアクセス制御
- ブルートフォース攻撃対策
- User-Agent 検証
- アクセスログ記録

### 🎛️ Web管理パネル
- 直感的なWebインターフェース
- リアルタイム監視と統計
- プロキシルール管理
- SSL証明書管理
- セキュリティ設定

### 🔄 グレースフル再起動
- ゼロダウンタイム再起動
- コネクション保持と状態復旧
- グレースフルシャットダウンメカニズム

## システム要件

- Linux システム (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 以上
- root 権限
- ポート 80 と 443 が利用可能

## クイックインストール

### 自動インストール

```bash
# インストールスクリプトをダウンロード
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh

# インストールスクリプトを実行
sudo bash install.sh
```

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

2. **Go のインストール**
```bash
# Go 1.21 をダウンロード・インストール
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

3. **SSLcat のコンパイル**
```bash
git clone https://github.com/xurenlu/sslcat.git
cd withssl
go mod download
go build -o withssl main.go
```

## 設定

### 基本設定

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password": "admin*9527",
    "first_run": true
  },
  "admin_prefix": "/sslcat-panel"
}
```

## 使用方法

### サービス開始
```bash
sudo systemctl start withssl
```

### サービス停止
```bash
sudo systemctl stop withssl
```

### Web管理パネル

1. ブラウザで `https://your-domain/sslcat-panel` にアクセス
2. デフォルト認証情報でログイン:
   - ユーザー名: `admin`
   - パスワード: `admin*9527`
3. 初回ログイン後にパスワードを変更

## コマンドライン引数

```bash
withssl --help
```

利用可能なオプション:
- `--config`: 設定ファイルパス (デフォルト: "/etc/sslcat/withssl.conf")
- `--admin-prefix`: 管理パネルパスプレフィックス (デフォルト: "/sslcat-panel")
- `--email`: SSL証明書メールアドレス
- `--port`: リスンポート (デフォルト: 443)
- `--host`: リスンアドレス (デフォルト: "0.0.0.0")
- `--version`: バージョン情報表示

## ライセンス

このプロジェクトは MIT ライセンスを使用しています。詳細は [LICENSE](LICENSE) ファイルを参照してください。

## サポート

問題が発生した場合や提案がある場合:
1. [Issues](https://github.com/xurenlu/sslcat/issues) を検索
2. 新しい Issue を作成
3. メンテナーに連絡
