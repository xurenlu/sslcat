#!/bin/bash
set -e

# 部署 CPU 修复版本到 shifen.de 服务器
# 此脚本会在服务器上编译新版本并重启服务

SERVER="rocky@shifen.de"
REMOTE_BUILD_DIR="/tmp/sslcat-build-$$"
REMOTE_INSTALL_DIR="/opt/sslcat"

echo "=== 部署 sslcat CPU 修复版本到 shifen.de ==="

# 1. 在服务器上创建临时构建目录
echo "[1/6] 创建临时构建目录..."
ssh $SERVER "mkdir -p $REMOTE_BUILD_DIR"

# 2. 复制源代码到服务器
echo "[2/6] 复制源代码到服务器..."
rsync -avz --exclude='.git' --exclude='build' --exclude='data' --exclude='dist' \
    --exclude='docker-data' --exclude='node_modules' \
    ./ $SERVER:$REMOTE_BUILD_DIR/

# 3. 在服务器上编译
echo "[3/6] 在服务器上编译（启用 CGO）..."
# 移除 go.mod 中的 toolchain 指令（Go 1.19 不支持）
ssh $SERVER "cd $REMOTE_BUILD_DIR && sed -i '/^toolchain/d' go.mod && CGO_ENABLED=1 go build -ldflags='-s -w' -o sslcat ."

# 4. 备份当前版本
echo "[4/6] 备份当前版本..."
BACKUP_NAME="sslcat.backup.$(date +%Y%m%d_%H%M%S)"
ssh $SERVER "sudo cp $REMOTE_INSTALL_DIR/sslcat $REMOTE_INSTALL_DIR/$BACKUP_NAME"

# 5. 停止服务、替换二进制文件、启动服务
echo "[5/6] 停止服务、替换二进制文件..."
ssh $SERVER "sudo systemctl stop sslcat && \
    sudo cp $REMOTE_BUILD_DIR/sslcat $REMOTE_INSTALL_DIR/sslcat && \
    sudo chmod +x $REMOTE_INSTALL_DIR/sslcat && \
    sudo systemctl start sslcat"

# 6. 清理临时文件
echo "[6/6] 清理临时文件..."
ssh $SERVER "rm -rf $REMOTE_BUILD_DIR"

echo ""
echo "=== 部署完成！==="
echo "备份文件: $BACKUP_NAME"
echo ""
echo "验证服务状态："
ssh $SERVER "sudo systemctl status sslcat --no-pager | head -15"

echo ""
echo "查看 CPU 使用情况（等待 10 秒后）："
sleep 10
ssh $SERVER "ps aux | grep -E 'PID|sslcat' | grep -v grep"

