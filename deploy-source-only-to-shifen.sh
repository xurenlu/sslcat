#!/bin/bash
set -e

# 仅部署源代码修改到 shifen.de 服务器
# 由于服务器 Go 版本过旧，我们只更新源代码，然后手动指导用户升级 Go 或使用 Docker 编译

SERVER="rocky@shifen.de"
REMOTE_DIR="/opt/sslcat"

echo "=== 部署 CPU 修复的源代码到 shifen.de ==="
echo ""
echo "注意：由于服务器 Go 版本为 1.19，无法直接编译。"
echo "此脚本仅更新源代码文件。"
echo ""

# 1. 备份并更新 main.go
echo "[1/3] 更新 main.go..."
ssh $SERVER "sudo cp $REMOTE_DIR/main.go $REMOTE_DIR/main.go.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true"
scp main.go $SERVER:/tmp/main.go.new
ssh $SERVER "sudo mv /tmp/main.go.new $REMOTE_DIR/main.go && sudo chown root:root $REMOTE_DIR/main.go"

# 2. 备份并更新 internal/proxy/manager.go
echo "[2/3] 更新 internal/proxy/manager.go..."
ssh $SERVER "sudo mkdir -p $REMOTE_DIR/internal/proxy"
ssh $SERVER "sudo cp $REMOTE_DIR/internal/proxy/manager.go $REMOTE_DIR/internal/proxy/manager.go.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true"
scp internal/proxy/manager.go $SERVER:/tmp/manager.go.new
ssh $SERVER "sudo mv /tmp/manager.go.new $REMOTE_DIR/internal/proxy/manager.go && sudo chown root:root $REMOTE_DIR/internal/proxy/manager.go"

echo "[3/3] 源代码更新完成"
echo ""
echo "=== 下一步操作 ==="
echo ""
echo "选项 1: 在服务器上升级 Go 到 1.21+ 然后编译"
echo "  ssh $SERVER"
echo "  # 升级 Go..."
echo "  cd $REMOTE_DIR"
echo "  sudo CGO_ENABLED=1 go build -ldflags='-s -w' -o sslcat ."
echo "  sudo systemctl restart sslcat"
echo ""
echo "选项 2: 在本地使用 Docker 编译（推荐）"
echo "  # 启动 Docker Desktop"
echo "  make docker-cgo-extract"
echo "  cp build/sslcat-linux-amd64-cgo build/sslcat-linux-amd64"
echo "  scp build/sslcat-linux-amd64 $SERVER:/tmp/sslcat.new"
echo "  ssh $SERVER 'sudo systemctl stop sslcat && sudo mv /tmp/sslcat.new $REMOTE_DIR/sslcat && sudo chmod +x $REMOTE_DIR/sslcat && sudo systemctl start sslcat'"
echo ""
echo "源代码已更新，等待编译部署。"

