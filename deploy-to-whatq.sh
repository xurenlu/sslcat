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

# 1. 检查构建文件是否存在
if [ ! -f "build/sslcat-linux-amd64" ]; then
    echo "❌ 构建文件不存在，请先运行: make build-linux"
    exit 1
fi

echo "✅ 找到构建文件: build/sslcat-linux-amd64"

# 2. 创建部署包
echo "📦 创建部署包..."
mkdir -p deploy
cp build/sslcat-linux-amd64 deploy/sslcat
cp sslcat.conf.example deploy/sslcat.conf
cp -r deploy/ deploy-backup/ 2>/dev/null || true

# 3. 创建服务文件
echo "⚙️  创建 systemd 服务文件..."
cat > deploy/sslcat.service << EOF
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=sslcat
Group=sslcat
WorkingDirectory=$TARGET_DIR
ExecStart=$TARGET_DIR/sslcat --config /etc/sslcat/sslcat.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sslcat

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sslcat /etc/sslcat $TARGET_DIR

[Install]
WantedBy=multi-user.target
EOF

# 4. 创建部署命令
cat > deploy/deploy-commands.sh << 'EOF'
#!/bin/bash

# 在目标服务器上运行的部署命令

set -e

echo "📁 创建目录和用户..."
useradd -r -s /bin/false sslcat || true
mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs,data}
chown -R sslcat:sslcat /var/lib/sslcat

echo "🛑 停止旧服务..."
systemctl stop sslcat || true

echo "📋 复制文件..."
mkdir -p /opt/sslcat
cp sslcat /opt/sslcat/sslcat-new
chmod +x /opt/sslcat/sslcat-new
chown -R sslcat:sslcat /opt/sslcat

echo "🔄 替换二进制文件..."
mv /opt/sslcat/sslcat-new /opt/sslcat/sslcat

echo "⚙️  安装服务..."
cp sslcat.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sslcat

echo "📝 配置文件..."
if [ ! -f /etc/sslcat/sslcat.conf ]; then
    cp sslcat.conf /etc/sslcat/
    chown sslcat:sslcat /etc/sslcat/sslcat.conf
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

echo "🛑 停止旧服务..."
systemctl stop sslcat || true

echo "🚀 启动服务..."
systemctl start sslcat
systemctl status sslcat

echo ""
echo "✅ SSLcat 部署完成！"
echo "管理面板: http://whatq.wxside.com/sslcat-panel/"
echo "默认用户名: admin"
echo "默认密码: admin*9527"
EOF

chmod +x deploy/deploy-commands.sh

echo "📤 部署包创建完成，包含以下文件："
echo "  - sslcat (二进制文件)"
echo "  - sslcat.conf (配置文件)"
echo "  - sslcat.service (systemd 服务文件)"
echo "  - deploy-commands.sh (服务器端部署脚本)"
echo ""

# 5. 上传到服务器
echo "📤 上传文件到服务器..."
scp -r deploy/ $TARGET_USER@$TARGET_HOST:/tmp/

echo "🚀 在服务器上执行部署..."
ssh $TARGET_USER@$TARGET_HOST 'cd /tmp/deploy && bash deploy-commands.sh'

echo ""
echo "✅ 部署完成！"
echo "管理面板: http://whatq.wxside.com/sslcat-panel/"
echo "默认用户名: admin"
echo "默认密码: admin*9527"
