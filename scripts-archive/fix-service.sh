#!/bin/bash

# SSLcat 服务配置修复脚本
# 修复systemd服务文件中的路径问题

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
echo "SSLcat 服务配置修复脚本"
echo "=========================================="

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   log_error "此脚本需要root权限运行"
   echo "请使用: sudo $0"
   exit 1
fi

# 检查服务是否存在
if ! systemctl list-unit-files | grep -q "withssl.service"; then
    log_error "SSLcat服务未安装，请先运行 install.sh"
    exit 1
fi

log_info "检测到SSLcat服务，开始修复..."

# 停止服务
log_info "停止SSLcat服务..."
systemctl stop withssl || true

# 备份原始服务文件
log_info "备份原始服务文件..."
cp /etc/systemd/system/withssl.service /etc/systemd/system/withssl.service.backup.$(date +%Y%m%d_%H%M%S)

# 创建修复后的服务文件
log_info "创建修复后的服务文件..."
cat > /etc/systemd/system/withssl.service << 'EOF'
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/withssl --config /etc/sslcat/withssl.conf
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
ReadWritePaths=/opt/sslcat /etc/sslcat /opt/sslcat

# 环境变量
Environment=GOPATH=/opt/go
Environment=PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd配置
log_info "重新加载systemd配置..."
systemctl daemon-reload

# 检查文件和权限
log_info "检查文件和权限..."

# 检查二进制文件
if [[ ! -f /opt/sslcat/withssl ]]; then
    log_error "二进制文件 /opt/sslcat/withssl 不存在"
    exit 1
fi

if [[ ! -x /opt/sslcat/withssl ]]; then
    log_warning "二进制文件没有执行权限，正在修复..."
    chmod +x /opt/sslcat/withssl
fi

# 检查配置文件
if [[ ! -f /etc/sslcat/withssl.conf ]]; then
    log_error "配置文件 /etc/sslcat/withssl.conf 不存在"
    log_info "请检查配置文件路径或重新运行安装脚本"
    exit 1
fi

# 检查用户和组
if ! id withssl &>/dev/null; then
    log_error "用户 withssl 不存在"
    log_info "正在创建用户和组..."
    useradd --system --no-create-home --shell /bin/false withssl
fi

# 检查目录权限
log_info "检查和修复目录权限..."
mkdir -p /opt/sslcat
chown -R withssl:withssl /opt/sslcat
chown -R withssl:withssl /etc/sslcat
chown -R withssl:withssl /opt/sslcat
chmod 755 /opt/sslcat
chmod 755 /etc/sslcat
chmod 755 /opt/sslcat

# 启动服务
log_info "启动SSLcat服务..."
systemctl enable withssl
systemctl start withssl

# 等待服务启动
sleep 3

# 检查服务状态
if systemctl is-active --quiet withssl; then
    log_success "SSLcat服务启动成功！"
    
    echo ""
    echo "=========================================="
    echo "🎉 服务修复完成！"
    echo "=========================================="
    echo ""
    echo "📋 修复内容："
    echo "✅ 修复了systemd服务文件路径问题"
    echo "✅ 配置文件路径: /etc/sslcat/withssl.conf"
    echo "✅ 二进制文件路径: /opt/sslcat/withssl"
    echo "✅ 数据目录: /opt/sslcat"
    echo "✅ 修复了文件权限"
    echo ""
    echo "🔍 服务状态："
    systemctl status withssl --no-pager -l
    echo ""
    echo "📝 常用命令："
    echo "  查看状态: sudo systemctl status withssl"
    echo "  查看日志: sudo journalctl -u withssl -f"
    echo "  重启服务: sudo systemctl restart withssl"
    echo "  停止服务: sudo systemctl stop withssl"
    
else
    log_error "服务启动失败，请查看日志："
    echo ""
    echo "systemctl status withssl"
    echo "journalctl -u withssl -n 50"
    echo ""
    echo "常见问题："
    echo "1. 检查端口是否被占用: netstat -tlnp | grep ':443'"
    echo "2. 检查配置文件语法: /opt/sslcat/withssl --config /etc/sslcat/withssl.conf --check"
    echo "3. 检查防火墙设置"
    exit 1
fi
