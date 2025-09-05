#!/usr/bin/env bash
set -euo pipefail

# withssl 一键安装脚本（Linux/macOS）
# 用法（推荐传版本）：
#   curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.0.3

VER=""
DEST_LINUX="/opt/sslcat"
CONF_LINUX="/etc/sslcat/withssl.conf"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      VER="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$VER" ]]; then
  echo "[withssl] 你未指定版本，默认安装 v1.0.3"
  VER="1.0.3"
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7|armhf) ARCH=arm ;;
  *) echo "[withssl] 不支持的架构: $ARCH_RAW" >&2; exit 1 ;;
esac

ASSET="withssl_${VER}_${OS}_${ARCH}"
EXT=".tar.gz"
if [[ "$OS" == "windows" ]]; then EXT=".zip"; fi
URL="https://github.com/xurenlu/sslcat/releases/download/v${VER}/${ASSET}${EXT}"

echo "[withssl] 下载: $URL"
TMP="$(mktemp -d)"
curl -fsSL "$URL" -o "$TMP/pkg${EXT}"

if [[ "$OS" == "darwin" ]]; then
  tar -xzf "$TMP/pkg${EXT}" -C "$TMP"
  sudo install -m 0755 "$TMP/withssl" /usr/local/bin/withssl
  echo "[withssl] 安装完成: /usr/local/bin/withssl"
  echo "[withssl] 运行: withssl --config withssl.conf --port 8080"
  exit 0
fi

# Linux: 安装到 /opt/sslcat 并写入 systemd 与默认配置
sudo mkdir -p "$DEST_LINUX" /var/lib/sslcat/{certs,keys,logs} /etc/sslcat
tar -xzf "$TMP/pkg${EXT}" -C "$TMP"
sudo install -m 0755 "$TMP/withssl" "$DEST_LINUX/withssl"

if [[ ! -f "$CONF_LINUX" ]]; then
  sudo bash -c "cat > $CONF_LINUX" <<'JSON'
{
  "server": {"host": "0.0.0.0", "port": 443, "debug": false},
  "ssl": {"staging": false, "cert_dir": "/var/lib/sslcat/certs", "key_dir": "/var/lib/sslcat/keys", "auto_renew": true},
  "admin": {"username": "admin", "first_run": true, "password_file": "/var/lib/sslcat/admin.pass"},
  "proxy": {"rules": []},
  "security": {"max_attempts": 3, "block_duration": "1m", "max_attempts_5min": 10, "block_file": "/var/lib/sslcat/withssl.block", "allowed_user_agents": ["Mozilla/","Chrome/","Firefox/","Safari/","Edge/"]},
  "admin_prefix": "/sslcat-panel"
}
JSON
fi

SERVICE=/etc/systemd/system/withssl.service
sudo bash -c "cat > $SERVICE" <<'UNIT'
[Unit]
Description=SSLcat Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/sslcat/withssl --config /etc/sslcat/withssl.conf
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable withssl || true
sudo systemctl restart withssl || sudo systemctl start withssl || true

echo "[withssl] 安装完成: /opt/sslcat/withssl"
echo "[withssl] 配置: /etc/sslcat/withssl.conf"
echo "[withssl] 管理面板: https://<你的域名或IP>/sslcat-panel/ (首次登录将强制改密)"


