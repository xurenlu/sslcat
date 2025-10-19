#!/bin/bash

# SSLcat 部署脚本

set -e

TARGET_HOST=${1:-"your-server.com"}
TARGET_USER=${2:-"root"}
TARGET_DIR="/opt/sslcat"

echo "==============================================="
echo "SSLcat 部署脚本"
echo "==============================================="
echo "目标服务器: $TARGET_USER@$TARGET_HOST"
echo "部署目录: $TARGET_DIR"
echo ""

# 1. 构建 Linux 64位二进制文件
echo "🔨 构建 SSLcat Linux 64位二进制文件..."
echo "   平台: linux/amd64"
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o withssl main.go

if [ $? -ne 0 ]; then
    echo "❌ 编译失败，请检查 Go 环境"
    exit 1
fi

echo "✅ Linux 64位二进制文件编译完成"

# 2. 创建部署包
echo "📦 创建部署包..."
mkdir -p deploy
cp withssl deploy/
cp sslcat.conf.example deploy/sslcat.conf
cp install.sh deploy/
cp README.md deploy/

# 3. 创建服务文件
echo "⚙️  创建 systemd 服务文件..."
cat > deploy/withssl.service << EOF
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=$TARGET_DIR
ExecStart=$TARGET_DIR/withssl --config /etc/sslcat/sslcat.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=withssl

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/sslcat /etc/sslcat $TARGET_DIR

[Install]
WantedBy=multi-user.target
EOF

# 4. 创建部署命令
cat > deploy/deploy-commands.sh << 'EOF'
#!/bin/bash

# 在目标服务器上运行的部署命令

set -e

echo "📁 创建目录和用户..."
useradd -r -s /bin/false withssl || true
mkdir -p /etc/sslcat /opt/sslcat/{certs,keys,logs}
chown -R withssl:withssl /opt/sslcat

echo "📋 复制文件..."
mkdir -p /opt/sslcat
cp withssl /opt/sslcat/
chmod +x /opt/sslcat/withssl
chown -R withssl:withssl /opt/sslcat

echo "⚙️  安装服务..."
cp withssl.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable withssl

echo "📝 配置文件..."
if [ ! -f /etc/sslcat/sslcat.conf ]; then
    cp sslcat.conf /etc/sslcat/
    chown withssl:withssl /etc/sslcat/sslcat.conf
    chmod 600 /etc/sslcat/sslcat.conf
fi

echo "🔧 配置防火墙..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp
    ufw allow 443/tcp
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --reload
fi

echo "🚀 启动服务..."
systemctl start withssl
systemctl status withssl

echo ""
echo "✅ SSLcat 部署完成！"
# 获取公网IP
PUBLIC_IP=$(curl -s https://ip4.dev/myip | tr -d '\n' | xargs)
echo "管理面板: http://$PUBLIC_IP:80/sslcat-panel/ 或 https://<你的域名>/sslcat-panel/"
echo "默认用户名: admin"
echo "默认密码: admin*9527"
EOF

chmod +x deploy/deploy-commands.sh

echo "📤 部署包创建完成，包含以下文件："
echo "  - withssl (二进制文件)"
echo "  - sslcat.conf (配置文件)"
echo "  - withssl.service (systemd 服务文件)"
echo "  - deploy-commands.sh (服务器端部署脚本)"
echo "  - install.sh (自动安装脚本)"
echo "  - README.md (说明文档)"
echo ""
echo "📋 部署到服务器："
echo "  1. 上传 deploy/ 目录到服务器"
echo "  2. 在服务器上运行: bash deploy-commands.sh"
echo ""
echo "📋 或使用 SCP 自动部署："
echo "  scp -r deploy/ $TARGET_USER@$TARGET_HOST:/tmp/"
echo "  ssh $TARGET_USER@$TARGET_HOST 'cd /tmp/deploy && bash deploy-commands.sh'"
echo ""
echo "注意: SSLcat 使用 CDN 资源，无需部署静态文件！"
