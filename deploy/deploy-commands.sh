#!/bin/bash

# WithSSL 服务器端一键部署脚本
# 在目标服务器上运行此脚本完成部署

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "=========================================="
echo "WithSSL 服务器端一键部署"
echo "=========================================="

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   log_error "此脚本需要root权限运行"
   echo "请使用: sudo $0"
   exit 1
fi

# 1. 创建系统用户和目录
log_info "创建系统用户和目录..."
if ! id withssl &>/dev/null; then
    useradd -r -s /bin/false withssl
    log_success "用户 withssl 创建成功"
else
    log_info "用户 withssl 已存在"
fi

# 创建必要目录
mkdir -p /etc/withssl /var/lib/withssl/{certs,keys,logs} /opt/withssl
chown -R withssl:withssl /var/lib/withssl
chown -R withssl:withssl /etc/withssl
log_success "目录创建完成"

# 2. 复制二进制文件
log_info "安装二进制文件..."
if [[ -f "withssl-linux" ]]; then
    cp withssl-linux /opt/withssl/withssl
elif [[ -f "withssl" ]]; then
    cp withssl /opt/withssl/withssl
else
    log_error "未找到 WithSSL 二进制文件"
    log_info "请确保 withssl 或 withssl-linux 文件在当前目录"
    exit 1
fi

chmod +x /opt/withssl/withssl
chown withssl:withssl /opt/withssl/withssl
log_success "二进制文件安装完成"

# 3. 安装配置文件
log_info "安装配置文件..."
if [[ ! -f /etc/withssl/withssl.conf ]]; then
    if [[ -f "withssl.conf" ]]; then
        cp withssl.conf /etc/withssl/
    elif [[ -f "withssl.conf.example" ]]; then
        cp withssl.conf.example /etc/withssl/withssl.conf
    else
        log_error "未找到配置文件"
        exit 1
    fi
    chown withssl:withssl /etc/withssl/withssl.conf
    chmod 600 /etc/withssl/withssl.conf
    log_success "配置文件安装完成"
else
    log_warning "配置文件已存在，跳过安装"
fi

# 4. 创建systemd服务文件
log_info "创建systemd服务..."
cat > /etc/systemd/system/withssl.service << 'EOF'
[Unit]
Description=WithSSL SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=/opt/withssl
ExecStart=/opt/withssl/withssl --config /etc/withssl/withssl.conf
ExecReload=/bin/kill -HUP $MAINPID
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
ReadWritePaths=/var/lib/withssl /etc/withssl /opt/withssl

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable withssl
log_success "systemd服务创建完成"

# 5. 配置防火墙
log_info "配置防火墙..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    log_success "UFW防火墙配置完成"
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    log_success "firewalld防火墙配置完成"
else
    log_warning "未检测到防火墙，请手动开放80和443端口"
fi

# 6. 启动服务
log_info "启动WithSSL服务..."
systemctl start withssl

# 等待服务启动
sleep 3

# 7. 检查服务状态
if systemctl is-active --quiet withssl; then
    log_success "WithSSL服务启动成功！"
    
    echo ""
    echo "=========================================="
    echo "🎉 WithSSL 部署完成！"
    echo "=========================================="
    echo ""
    echo "📋 部署信息："
    echo "  二进制文件: /opt/withssl/withssl"
    echo "  配置文件: /etc/withssl/withssl.conf"
    echo "  数据目录: /var/lib/withssl/"
    echo "  服务用户: withssl"
    echo ""
    echo "🌐 访问信息："
    echo "  管理面板: https://your-domain/withssl-panel/"
    echo "  默认用户名: admin"
    echo "  默认密码: admin*9527"
    echo ""
    echo "📊 服务状态："
    systemctl status withssl --no-pager -l
    echo ""
    echo "📝 常用命令："
    echo "  查看状态: sudo systemctl status withssl"
    echo "  查看日志: sudo journalctl -u withssl -f"
    echo "  重启服务: sudo systemctl restart withssl"
    echo "  停止服务: sudo systemctl stop withssl"
    echo ""
    echo "⚙️  配置文件: /etc/withssl/withssl.conf"
    echo "请根据需要修改配置文件并重启服务"
    
else
    log_error "WithSSL服务启动失败"
    echo ""
    echo "🔍 故障排除："
    echo "  查看服务状态: sudo systemctl status withssl"
    echo "  查看详细日志: sudo journalctl -u withssl -n 50"
    echo "  检查配置文件: sudo /opt/withssl/withssl --config /etc/withssl/withssl.conf --check"
    echo ""
    echo "常见问题："
    echo "1. 端口占用: netstat -tlnp | grep ':443'"
    echo "2. 权限问题: ls -la /opt/withssl/withssl"
    echo "3. 配置错误: 检查 /etc/withssl/withssl.conf"
    exit 1
fi
