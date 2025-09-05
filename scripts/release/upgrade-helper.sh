#!/usr/bin/env bash
set -euo pipefail

# 简易升级助手：下载指定版本、备份当前、平滑替换、可回滚

REPO=${REPO:-xurenlu/sslcat}
VER=${VER:-1.0.4}
BIN_URL=${BIN_URL:-"https://github.com/${REPO}/releases/download/v${VER}/sslcat_${VER}_linux_amd64.tar.gz"}
DEST=/opt/sslcat
CONF=/etc/sslcat/sslcat.conf
BACKUP_DIR=${BACKUP_DIR:-/opt/sslcat-backups}

echo "==> Downloading ${BIN_URL}"
mkdir -p "$BACKUP_DIR" "$DEST"
TMP=$(mktemp -d)
curl -fsSL "$BIN_URL" -o "$TMP/sslcat.tgz"
tar -xzf "$TMP/sslcat.tgz" -C "$TMP"

echo "==> Backing up current binary"
if [ -f "$DEST/sslcat" ]; then
  ts=$(date -u +%Y%m%d-%H%M%S)
  mkdir -p "$BACKUP_DIR/$ts"
  cp -a "$DEST/sslcat" "$BACKUP_DIR/$ts/sslcat"
fi

echo "==> Replacing binary"
install -m 0755 "$TMP/sslcat" "$DEST/sslcat"

echo "==> Restarting service"
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart sslcat || true
fi

echo "Upgrade ok. To rollback: copy a previous backup from $BACKUP_DIR back to $DEST/sslcat and restart service."

