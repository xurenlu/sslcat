#!/bin/bash

# SSLcat 部署到 s2.shifen.de 服务器

set -e

TARGET_HOST="s2.shifen.de"
TARGET_USER="rocky"
TARGET_DIR="/opt/sslcat"

echo "==============================================="
echo "SSLcat 部署到 s2.shifen.de"
echo "==============================================="
echo "目标服务器: $TARGET_USER@$TARGET_HOST"
echo "部署目录: $TARGET_DIR"
echo ""

# 0. 检查并同步远程配置文件
if [ -f "deploy-s2/sslcat.conf" ]; then
    source scripts/deploy-config-check.sh
    check_remote_config "$TARGET_HOST" "$TARGET_USER" "deploy-s2/sslcat.conf"
    echo ""
fi

# 1. 检查构建文件是否存在
if [ ! -f "build/sslcat-linux-amd64" ]; then
    echo "❌ 构建文件不存在，请先运行: make docker-cgo-extract"
    exit 1
fi

echo "✅ 找到构建文件: build/sslcat-linux-amd64"

# 2. 创建部署包
echo "📦 创建部署包..."
mkdir -p deploy-s2/scripts
cp build/sslcat-linux-amd64 deploy-s2/sslcat
cp sslcat.conf.example deploy-s2/sslcat.conf
cp scripts/sslcat-git-hook deploy-s2/scripts/

# 3. 创建服务文件
echo "⚙️  创建 systemd 服务文件..."
cat > deploy-s2/sslcat.service << EOF
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=root
Group=root
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
ProtectHome=false
ReadWritePaths=/opt/sslcat /etc/sslcat $TARGET_DIR /home/git

[Install]
WantedBy=multi-user.target
EOF

# 4. 创建部署命令
cat > deploy-s2/deploy-commands.sh << 'EOF'
#!/bin/bash

# 在目标服务器上运行的部署命令

set -e

echo "📁 创建目录和用户..."
sudo useradd -r -s /bin/false sslcat 2>/dev/null || true
sudo mkdir -p /etc/sslcat /opt/sslcat/{certs,keys,logs,data,repos} /opt/sslcat
sudo chown -R sslcat:sslcat /opt/sslcat

echo "📁 创建 Git 用户..."
# 查找 git-shell 路径
GIT_SHELL_PATH=$(which git-shell || echo "/usr/bin/git-shell")
# 创建 git 用户，用于 Git Deploy Server
if ! id -u git &>/dev/null; then
    sudo useradd -r -s "$GIT_SHELL_PATH" -m -d /home/git git 2>/dev/null || echo "git 用户可能已存在"
    sudo mkdir -p /home/git/.ssh
    sudo chmod 700 /home/git/.ssh
    sudo touch /home/git/.ssh/authorized_keys
    sudo chmod 600 /home/git/.ssh/authorized_keys
    sudo chown -R git:git /home/git
    echo "✅ git 用户创建成功"
else
    echo "✅ git 用户已存在"
    # 确保目录存在
    sudo mkdir -p /home/git/.ssh
    sudo chmod 700 /home/git/.ssh
    sudo chown -R git:git /home/git/.ssh
fi

echo "🔧 安装依赖..."
# 检查是否已安装 musl
if ! dpkg -l | grep -q "^ii  musl "; then
    echo "安装 musl 库..."
    sudo apt-get update
    sudo apt-get install -y musl
fi

echo "🛑 停止旧服务..."
sudo systemctl stop sslcat 2>/dev/null || true

echo "📋 复制文件..."
sudo cp sslcat /opt/sslcat/sslcat-new
sudo chmod +x /opt/sslcat/sslcat-new
sudo chown sslcat:sslcat /opt/sslcat/sslcat-new

echo "🔄 替换二进制文件..."
sudo mv /opt/sslcat/sslcat-new /opt/sslcat/sslcat

echo "🔐 设置 capabilities..."
sudo setcap 'cap_net_bind_service=+ep' /opt/sslcat/sslcat

echo "⚙️  安装服务..."
sudo cp sslcat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sslcat

echo "📝 配置文件..."
if [ ! -f /etc/sslcat/sslcat.conf ]; then
    sudo cp sslcat.conf /etc/sslcat/
    sudo chmod 600 /etc/sslcat/sslcat.conf
    echo "✅ 配置文件已安装"
    echo "⚠️  请编辑 /etc/sslcat/sslcat.conf 配置文件"
else
    echo "⚠️  配置文件已存在，检查更新..."
    
    # 检查配置文件修改时间
    REMOTE_CONF_TIME=$(stat -c %Y /etc/sslcat/sslcat.conf 2>/dev/null || stat -f %m /etc/sslcat/sslcat.conf 2>/dev/null)
    LOCAL_CONF_TIME=$(stat -c %Y sslcat.conf 2>/dev/null || stat -f %m sslcat.conf 2>/dev/null)
    
    # 比较 MD5 或内容差异
    REMOTE_MD5=$(md5sum /etc/sslcat/sslcat.conf 2>/dev/null | awk '{print $1}' || md5 -q /etc/sslcat/sslcat.conf 2>/dev/null)
    LOCAL_MD5=$(md5sum sslcat.conf 2>/dev/null | awk '{print $1}' || md5 -q sslcat.conf 2>/dev/null)
    
    if [ "$REMOTE_MD5" = "$LOCAL_MD5" ]; then
        echo "✅ 配置文件无变化，跳过更新"
    elif [ "$REMOTE_CONF_TIME" -gt "$LOCAL_CONF_TIME" ]; then
        echo "⚠️  警告：线上配置文件比本地新！"
        echo "   线上修改时间: $(date -d @$REMOTE_CONF_TIME 2>/dev/null || date -r $REMOTE_CONF_TIME 2>/dev/null)"
        echo "   本地修改时间: $(date -d @$LOCAL_CONF_TIME 2>/dev/null || date -r $LOCAL_CONF_TIME 2>/dev/null)"
        echo ""
        echo "   已将本地配置保存到: /etc/sslcat/sslcat.conf.local-upload.\$(date +%Y%m%d_%H%M%S)"
        echo "   线上配置保持不变，请手动合并配置文件"
        sudo cp sslcat.conf /etc/sslcat/sslcat.conf.local-upload.\$(date +%Y%m%d_%H%M%S)
        echo "⏭️  跳过配置文件覆盖"
    else
        echo "📝 本地配置较新，更新线上配置..."
        BACKUP_FILE="/etc/sslcat/sslcat.conf.backup.\$(date +%Y%m%d_%H%M%S)"
        sudo cp /etc/sslcat/sslcat.conf "\$BACKUP_FILE"
        sudo cp sslcat.conf /etc/sslcat/
        sudo chmod 600 /etc/sslcat/sslcat.conf
        echo "✅ 配置文件已更新"
        echo "   旧配置已备份到: \$BACKUP_FILE"
    fi
fi

echo "📜 安装 Git Hook 脚本..."
# 复制 Git hook 脚本到多个位置以确保能找到
sudo mkdir -p /opt/sslcat/scripts
sudo cp scripts/sslcat-git-hook /opt/sslcat/scripts/
sudo chmod +x /opt/sslcat/scripts/sslcat-git-hook
# 同时复制到标准位置
sudo cp scripts/sslcat-git-hook /usr/local/bin/
sudo chmod +x /usr/local/bin/sslcat-git-hook
echo "✅ Git Hook 脚本已安装"

echo "🔧 配置防火墙..."
if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 80/tcp 2>/dev/null || true
    sudo ufw allow 443/tcp 2>/dev/null || true
    sudo ufw allow 2222/tcp 2>/dev/null || true
elif command -v firewall-cmd >/dev/null 2>&1; then
    sudo firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
    sudo firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
    sudo firewall-cmd --permanent --add-port=2222/tcp 2>/dev/null || true
    sudo firewall-cmd --reload 2>/dev/null || true
fi

echo "🚀 启动服务..."
sudo systemctl start sslcat
sleep 2
sudo systemctl status sslcat

echo ""
echo "✅ SSLcat 部署完成！"
echo "管理面板: http://s2.shifen.de/sslcat-panel/"
echo "默认用户名: admin"
echo "默认密码: admin*9527"
echo ""
echo "Git 部署域名格式: [app].s2.shifen.de"
echo "Git SSH 端口: 2222"
EOF

chmod +x deploy-s2/deploy-commands.sh

echo "📤 部署包创建完成，包含以下文件："
echo "  - sslcat (二进制文件)"
echo "  - sslcat.conf (配置文件)"
echo "  - sslcat.service (systemd 服务文件)"
echo "  - deploy-commands.sh (服务器端部署脚本)"
echo ""

# 5. 上传到服务器
echo "📤 上传文件到服务器..."
scp -r deploy-s2/ $TARGET_USER@$TARGET_HOST:/tmp/

echo "🚀 在服务器上执行部署..."
ssh $TARGET_USER@$TARGET_HOST 'cd /tmp/deploy-s2 && bash deploy-commands.sh'

echo ""
echo "✅ 部署完成！"
echo "管理面板: http://s2.shifen.de/sslcat-panel/"
echo "主域名: s2.shifen.de"
echo "应用域名格式: [app].s2.shifen.de"
echo ""
echo "后续配置："
echo "1. 编辑 /etc/sslcat/sslcat.conf 配置域名"
echo "2. 配置 DNS 解析：*.s2.shifen.de -> 服务器 IP"
echo "3. 重启服务：sudo systemctl restart sslcat"
