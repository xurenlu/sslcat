#!/bin/bash

# 在目标服务器上运行的部署命令

set -e

echo "📁 创建目录和用户..."
useradd -r -s /bin/false withssl || true
mkdir -p /etc/withssl /var/lib/withssl/{certs,keys,logs}
chown -R withssl:withssl /var/lib/withssl

echo "📋 复制文件..."
mkdir -p /opt/withssl
cp withssl /opt/withssl/
chmod +x /opt/withssl/withssl
chown -R withssl:withssl /opt/withssl

echo "⚙️  安装服务..."
cp withssl.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable withssl

echo "📝 配置文件..."
if [ ! -f /etc/withssl/withssl.conf ]; then
    cp withssl.conf /etc/withssl/
    chown withssl:withssl /etc/withssl/withssl.conf
    chmod 600 /etc/withssl/withssl.conf
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
echo "✅ WithSSL 部署完成！"
echo "管理面板: https://your-domain/withssl-panel/"
echo "默认用户名: admin"
echo "默认密码: admin*9527"
