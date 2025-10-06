#!/bin/bash

# SSLcat 部署到 shifen.de 服务器

set -e

TARGET_HOST="shifen.de"
TARGET_USER="rocky"
TARGET_DIR="/opt/sslcat"

echo "==============================================="
echo "SSLcat 部署到 shifen.de"
echo "==============================================="
echo "目标服务器: $TARGET_USER@$TARGET_HOST"
echo "部署目录: $TARGET_DIR"
echo ""

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
mkdir -p deploy-shifen/scripts
cp build/sslcat-linux-amd64 deploy-shifen/sslcat

# 3. 复制 Git Hook 脚本（如果存在）
if [ -f "scripts/sslcat-git-hook" ]; then
    cp scripts/sslcat-git-hook deploy-shifen/scripts/
    echo "✅ Git Hook 脚本已包含"
else
    echo "⚠️  未找到 Git Hook 脚本，跳过..."
fi

# 4. 设置执行权限
chmod +x deploy-shifen/deploy-commands.sh

echo "📤 部署包内容："
echo "  - sslcat (二进制文件)"
echo "  - sslcat.conf (配置文件)"
echo "  - sslcat.service (systemd 服务文件)"
echo "  - deploy-commands.sh (服务器端部署脚本)"
if [ -f "deploy-shifen/scripts/sslcat-git-hook" ]; then
    echo "  - scripts/sslcat-git-hook (Git Hook 脚本)"
fi
echo ""

# 5. 上传到服务器
echo "📤 上传文件到服务器..."
scp -r deploy-shifen/ $TARGET_USER@$TARGET_HOST:/tmp/

echo ""
echo "🚀 在服务器上执行部署..."
ssh $TARGET_USER@$TARGET_HOST 'cd /tmp/deploy-shifen && bash deploy-commands.sh'

echo ""
echo "==============================================="
echo "✅ 部署完成！"
echo "==============================================="
echo ""
echo "📊 服务信息："
echo "  管理面板: https://shifen.de/sslcat-panel/"
echo "  主域名: shifen.de"
echo ""
echo "🌐 已配置的域名："
echo "  - face.some.im -> localhost:3300"
echo "  - facev.app -> localhost:4000"
echo "  - faceapi.some.im -> localhost:3300"
echo "  - b2.some.im -> localhost:3899"
echo "  - console.mergely.app -> localhost:3500"
echo "  - api.ip4.dev -> localhost:7654"
echo "  - api.getanswer.xyz -> localhost:3377"
echo "  - gg.some.im -> /var/www/gg.some.im (静态文件)"
echo "  - api.myownx.com -> localhost:8812"
echo "  - api.some.im -> localhost:8815"
echo "  - api.cliptxt.com -> localhost:8816"
echo "  - cookie.some.im -> localhost:8088"
echo "  - dev.trydress.me -> localhost:6000"
echo "  - ff.cliptxt.com -> localhost:5000"
echo "  - ws.some.im -> localhost:8817"
echo "  - aliaudio.some.im -> localhost:8841"
echo "  - pdf.some.im -> localhost:8080"
echo "  - timely.some.im -> localhost:7321"
echo "  - kun.shifen.de -> localhost:8846"
echo "  - zhan.shifen.de -> localhost:4412"
echo "  - proxy.some.im -> OSS (sz-trans)"
echo ""
echo "🔧 Git 部署："
echo "  应用域名格式: [app].shifen.de"
echo "  SSH 端口: 2222"
echo ""
echo "📝 后续配置："
echo "  1. 确保所有域名的 DNS 解析已正确配置"
echo "  2. 确保所有后端服务 (3300, 4000, 3899, 等) 正在运行"
echo "  3. 检查服务状态：ssh $TARGET_USER@$TARGET_HOST 'sudo systemctl status sslcat'"
echo "  4. 查看日志：ssh $TARGET_USER@$TARGET_HOST 'sudo journalctl -u sslcat -f'"
echo "  5. 如需修改配置："
echo "     - 编辑本地 deploy-shifen/sslcat.conf"
echo "     - 重新运行此脚本部署"
echo ""

