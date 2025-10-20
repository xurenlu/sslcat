#!/bin/bash

# SSLcat 部署到 whatq.wxside.com 服务器

set -e

TARGET_HOST="whatq.wxside.com"
TARGET_USER="root"
TARGET_DIR="/opt/sslcat"

echo "==============================================="
echo "SSLcat 部署到 whatq.wxside.com"
echo "==============================================="
echo "目标服务器: $TARGET_USER@$TARGET_HOST"
echo "部署目录: $TARGET_DIR"
echo ""

# 0. 检查并同步远程配置文件
if [ -f "deploy-whatq/sslcat.conf" ]; then
    source scripts/deploy-config-check.sh
    check_remote_config "$TARGET_HOST" "$TARGET_USER" "deploy-whatq/sslcat.conf"
    echo ""
fi

# 1. 检查构建文件是否存在
if [ ! -f "build/sslcat-linux-amd64" ]; then
    echo "❌ 构建文件不存在，开始构建..."
    echo "运行: make docker-cgo-extract"
    make docker-cgo-extract
fi

if [ ! -f "build/sslcat-linux-amd64" ]; then
    echo "❌ 构建失败，无法找到构建文件"
    exit 1
fi

echo "✅ 找到构建文件: build/sslcat-linux-amd64"

# 2. 创建部署包
echo "📦 准备部署包..."
mkdir -p deploy-whatq/scripts
cp build/sslcat-linux-amd64 deploy-whatq/sslcat

# 3. 复制 Git Hook 脚本（如果存在）
if [ -f "scripts/sslcat-git-hook" ]; then
    cp scripts/sslcat-git-hook deploy-whatq/scripts/
    echo "✅ Git Hook 脚本已包含"
else
    echo "⚠️  未找到 Git Hook 脚本，跳过..."
fi

# 4. 设置执行权限
chmod +x deploy-whatq/deploy-commands.sh
chmod +x deploy-whatq/scripts/sslcat-git-hook 2>/dev/null || true

echo "📤 部署包内容："
echo "  - sslcat (二进制文件)"
echo "  - sslcat.conf (配置文件)"
echo "  - sslcat.service (systemd 服务文件)"
echo "  - deploy-commands.sh (服务器端部署脚本)"
if [ -f "deploy-whatq/scripts/sslcat-git-hook" ]; then
    echo "  - scripts/sslcat-git-hook (Git Hook 脚本)"
fi
echo ""

# 5. 上传到服务器
echo "📤 上传文件到服务器..."
scp -r deploy-whatq/ $TARGET_USER@$TARGET_HOST:/tmp/

echo ""
echo "🚀 在服务器上执行部署..."
ssh $TARGET_USER@$TARGET_HOST 'cd /tmp/deploy-whatq && bash deploy-commands.sh'

echo ""
echo "==============================================="
echo "✅ 部署完成！"
echo "==============================================="
echo ""
echo "📊 服务信息："
echo "  管理面板: https://whatq.wxside.com/sslcat-panel/"
echo "  主域名: whatq.wxside.com"
echo "  默认用户名: admin"
echo "  默认密码: admin*9527"
echo ""
echo "🔧 Git 部署："
echo "  应用域名格式: [app].whatq.wxside.com"
echo "  SSH 端口: 2222"
echo ""
echo "📝 后续配置："
echo "  1. 确保域名 whatq.wxside.com 和 *.whatq.wxside.com 的 DNS 解析已正确配置"
echo "  2. 检查服务状态：ssh $TARGET_USER@$TARGET_HOST 'sudo systemctl status sslcat'"
echo "  3. 查看日志：ssh $TARGET_USER@$TARGET_HOST 'sudo journalctl -u sslcat -f'"
echo "  4. 如需修改配置："
echo "     - 编辑本地 deploy-whatq/sslcat.conf"
echo "     - 重新运行此脚本部署"
echo "  5. 通过管理面板添加代理规则和应用"
echo ""
