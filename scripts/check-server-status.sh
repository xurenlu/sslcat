#!/bin/bash

# 服务器端 SSLcat 状态检查脚本
# 在 sg2.shifen.de 服务器上运行此脚本

echo "=== SSLcat 服务器状态检查 ==="
echo ""

# 1. 检查 sslcat 进程是否运行
echo "1. 检查 sslcat 进程..."
if pgrep -x sslcat > /dev/null; then
    echo "✓ SSLcat 进程正在运行"
    ps aux | grep sslcat | grep -v grep
else
    echo "✗ SSLcat 进程未运行"
fi
echo ""

# 2. 检查端口监听状态
echo "2. 检查端口监听状态..."
echo "检查 80 端口..."
if netstat -tlnp 2>/dev/null | grep -q ":80 "; then
    echo "✓ 80 端口正在监听"
    netstat -tlnp 2>/dev/null | grep ":80 "
else
    echo "✗ 80 端口未监听"
fi
echo ""

echo "检查 443 端口..."
if netstat -tlnp 2>/dev/null | grep -q ":443 "; then
    echo "✓ 443 端口正在监听"
    netstat -tlnp 2>/dev/null | grep ":443 "
else
    echo "✗ 443 端口未监听"
    echo "  提示：标准模式需要 root 权限监听 80/443 端口"
fi
echo ""

# 3. 使用 ss 命令检查（如果可用）
if command -v ss > /dev/null; then
    echo "3. 使用 ss 命令检查监听端口..."
    ss -tlnp | grep -E ":(80|443) "
    echo ""
fi

# 4. 检查防火墙状态
echo "4. 检查防火墙状态..."
if command -v ufw > /dev/null; then
    echo "UFW 防火墙状态："
    sudo ufw status | head -5
    echo ""
elif command -v firewall-cmd > /dev/null; then
    echo "firewalld 状态："
    sudo firewall-cmd --list-all 2>/dev/null | head -10
    echo ""
elif command -v iptables > /dev/null; then
    echo "iptables 规则（443 端口）："
    sudo iptables -L -n | grep -E "443|ACCEPT|REJECT|DROP" | head -10
    echo ""
fi

# 5. 检查 sslcat 服务状态（systemd）
echo "5. 检查 systemd 服务状态..."
if systemctl list-units --type=service 2>/dev/null | grep -q sslcat; then
    echo "SSLcat 服务状态："
    sudo systemctl status sslcat --no-pager -l | head -20
else
    echo "未找到 sslcat systemd 服务"
fi
echo ""

# 6. 检查配置文件
echo "6. 检查配置文件..."
CONFIG_FILE="/etc/sslcat/sslcat.conf"
if [ -f "$CONFIG_FILE" ]; then
    echo "✓ 配置文件存在: $CONFIG_FILE"
    echo "端口模式配置："
    grep -E "port_mode|enable_https|custom_port" "$CONFIG_FILE" | head -5 || echo "  未找到端口配置"
else
    echo "✗ 配置文件不存在: $CONFIG_FILE"
    echo "尝试查找其他位置的配置文件..."
    find /etc /opt /usr/local -name "sslcat.conf" 2>/dev/null | head -5
fi
echo ""

# 7. 检查证书目录
echo "7. 检查证书目录..."
CERT_DIR="/etc/sslcat/certs"
if [ -d "$CERT_DIR" ]; then
    echo "✓ 证书目录存在: $CERT_DIR"
    echo "证书文件（sg2.shifen.de）："
    ls -lh "$CERT_DIR"/sg2.shifen.de.* 2>/dev/null || echo "  未找到 sg2.shifen.de 的证书"
else
    echo "✗ 证书目录不存在: $CERT_DIR"
fi
echo ""

# 8. 检查日志
echo "8. 检查最近的日志..."
if [ -f "/var/log/sslcat/sslcat.log" ]; then
    echo "最近 20 行日志："
    tail -20 /var/log/sslcat/sslcat.log
elif [ -f "/etc/sslcat/sslcat.log" ]; then
    echo "最近 20 行日志："
    tail -20 /etc/sslcat/sslcat.log
elif journalctl -u sslcat > /dev/null 2>&1; then
    echo "最近的 systemd 日志："
    sudo journalctl -u sslcat -n 20 --no-pager
else
    echo "未找到日志文件"
fi
echo ""

# 9. 本地测试连接
echo "9. 本地测试连接..."
echo "测试本地 443 端口..."
if timeout 2 bash -c "echo > /dev/tcp/localhost/443" 2>/dev/null; then
    echo "✓ 本地 443 端口可连接"
else
    echo "✗ 本地 443 端口不可连接"
fi

echo "测试本地 80 端口..."
if timeout 2 bash -c "echo > /dev/tcp/localhost/80" 2>/dev/null; then
    echo "✓ 本地 80 端口可连接"
else
    echo "✗ 本地 80 端口不可连接"
fi
echo ""

echo "=== 检查完成 ==="
echo ""
echo "建议："
echo "1. 如果进程未运行，使用 sudo systemctl start sslcat 启动"
echo "2. 如果端口未监听，检查是否有 root 权限"
echo "3. 如果防火墙阻止，开放 80/443 端口"
echo "4. 查看日志获取详细错误信息"



