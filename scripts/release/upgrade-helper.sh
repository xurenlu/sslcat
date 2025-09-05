#!/usr/bin/env bash
set -euo pipefail

# 简易升级助手：下载指定版本、备份当前、平滑替换、可回滚

REPO=${REPO:-xurenlu/withssl}
VER=${VER:-1.0.1}
BIN_URL=${BIN_URL:-"https://github.com/${REPO}/releases/download/v${VER}/withssl_${VER}_linux_amd64.tar.gz"}
DEST=/opt/withssl
CONF=/etc/withssl/withssl.conf
BACKUP_DIR=${BACKUP_DIR:-/opt/withssl-backups}

echo "==> Downloading ${BIN_URL}"
mkdir -p "$BACKUP_DIR" "$DEST"
TMP=$(mktemp -d)
curl -fsSL "$BIN_URL" -o "$TMP/withssl.tgz"
tar -xzf "$TMP/withssl.tgz" -C "$TMP"

echo "==> Backing up current binary"
if [ -f "$DEST/withssl" ]; then
  ts=$(date -u +%Y%m%d-%H%M%S)
  mkdir -p "$BACKUP_DIR/$ts"
  cp -a "$DEST/withssl" "$BACKUP_DIR/$ts/withssl"
fi

echo "==> Replacing binary"
install -m 0755 "$TMP/withssl" "$DEST/withssl"

echo "==> Restarting service"
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart withssl || true
fi

echo "Upgrade ok. To rollback: copy a previous backup from $BACKUP_DIR back to $DEST/withssl and restart service."

