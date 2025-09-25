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
