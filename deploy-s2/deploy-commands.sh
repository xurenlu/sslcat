#!/bin/bash

# 在目标服务器上运行的部署命令

set -e

echo "📁 创建目录和用户..."
sudo useradd -r -s /bin/false sslcat 2>/dev/null || true
sudo mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs,data,repos} /opt/sslcat
sudo chown -R sslcat:sslcat /var/lib/sslcat

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
    echo "⚠️  请编辑 /etc/sslcat/sslcat.conf 配置文件"
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
