#!/bin/bash

# SSLcat 安装脚本
# 支持 Ubuntu/Debian 和 CentOS/RHEL 系统

set -e

# 颜色定义
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

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 检测操作系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    
    log_info "检测到操作系统: $OS $VERSION"
}

# 安装依赖
install_dependencies() {
    log_info "安装系统依赖..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl wget git build-essential ca-certificates
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y curl wget git gcc gcc-c++ make ca-certificates
            ;;
        *)
            log_error "不支持的操作系统: $OS"
            exit 1
            ;;
    esac
    
    log_success "系统依赖安装完成"
}

# 安装Go
install_go() {
    log_info "检查Go环境..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go已安装，版本: $GO_VERSION"
        
        # 检查版本是否满足要求
        if [[ $(echo "$GO_VERSION 1.21" | awk '{print ($1 >= $2)}') == 1 ]]; then
            log_success "Go版本满足要求"
            return 0
        else
            log_warning "Go版本过低，需要升级到1.21或更高版本"
        fi
    fi
    
    log_info "安装Go 1.21..."
    
    # 下载Go
    cd /tmp
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    
    # 设置环境变量
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export GOPATH=/opt/go' >> /etc/profile
    echo 'export GOBIN=$GOPATH/bin' >> /etc/profile
    
    # 创建Go工作目录
    mkdir -p /opt/go/{bin,src,pkg}
    
    # 设置当前会话的环境变量
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=/opt/go
    export GOBIN=$GOPATH/bin
    
    log_success "Go安装完成"
}

# 安装certbot
install_certbot() {
    log_info "安装certbot..."
    
    case $OS in
        ubuntu|debian)
            apt-get install -y certbot
            ;;
        centos|rhel|fedora)
            yum install -y certbot
            ;;
    esac
    
    log_success "certbot安装完成"
}

# 创建用户和目录
create_user_and_dirs() {
    log_info "创建withssl用户和目录..."
    
    # 创建用户
    if ! id "withssl" &>/dev/null; then
        useradd -r -s /bin/false withssl
        log_success "创建withssl用户"
    else
        log_info "withssl用户已存在"
    fi
    
    # 创建目录
    mkdir -p /etc/sslcat
    mkdir -p /var/lib/sslcat/{certs,keys,logs}
    mkdir -p /opt/sslcat
    
    # 设置权限
    chown -R withssl:withssl /var/lib/sslcat
    chmod 755 /etc/sslcat
    chmod 700 /var/lib/sslcat
    
    log_success "目录创建完成"
}

# 编译SSLcat
build_withssl() {
    log_info "编译SSLcat..."
    
    # 设置Go环境变量
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=/opt/go
    export GOBIN=$GOPATH/bin
    
    # 进入项目目录
    cd /opt/sslcat
    
    # 下载依赖
    log_info "下载Go依赖..."
    go mod download
    
    # 编译
    log_info "编译二进制文件..."
    go build -o withssl main.go
    
    # 设置权限
    chmod +x withssl
    chown withssl:withssl withssl
    
    log_success "SSLcat编译完成"
}

# 创建systemd服务
create_systemd_service() {
    log_info "创建systemd服务..."
    
    cat > /etc/systemd/system/withssl.service << EOF
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/withssl --config /etc/sslcat/withssl.conf
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
ReadWritePaths=/var/lib/sslcat /etc/sslcat /opt/sslcat

# 环境变量
Environment=GOPATH=/opt/go
Environment=PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd
    systemctl daemon-reload
    
    log_success "systemd服务创建完成"
}

# 创建配置文件
create_config() {
    log_info "创建默认配置文件..."
    
    cat > /etc/sslcat/withssl.conf << EOF
server:
  host: "0.0.0.0"
  port: 443
  debug: false

ssl:
  email: ""
  staging: false
  domains: []
  cert_dir: "/var/lib/sslcat/certs"
  key_dir: "/var/lib/sslcat/keys"
  auto_renew: true

admin:
  username: "admin"
  password: "admin*9527"
  first_run: true

proxy:
  rules: []

security:
  max_attempts: 3
  block_duration: "1m"
  max_attempts_5min: 10
  block_file: "/var/lib/sslcat/withssl.block"
  allowed_user_agents:
    - "Mozilla/"
    - "Chrome/"
    - "Firefox/"
    - "Safari/"
    - "Edge/"

admin_prefix: "/sslcat-panel"
EOF
    
    chown withssl:withssl /etc/sslcat/withssl.conf
    chmod 600 /etc/sslcat/withssl.conf
    
    log_success "配置文件创建完成"
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    # 检查防火墙状态
    if systemctl is-active --quiet ufw; then
        log_info "配置UFW防火墙..."
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw --force enable
    elif systemctl is-active --quiet firewalld; then
        log_info "配置firewalld防火墙..."
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    elif command -v iptables &> /dev/null; then
        log_info "配置iptables防火墙..."
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    else
        log_warning "未检测到防火墙，请手动开放80和443端口"
    fi
    
    log_success "防火墙配置完成"
}

# 启动服务
start_service() {
    log_info "启动SSLcat服务..."
    
    systemctl enable withssl
    systemctl start withssl
    
    # 等待服务启动
    sleep 3
    
    if systemctl is-active --quiet withssl; then
        log_success "SSLcat服务启动成功"
    else
        log_error "SSLcat服务启动失败"
        systemctl status withssl
        exit 1
    fi
}

# 显示安装信息
show_install_info() {
    log_success "SSLcat安装完成！"
    echo
    echo "=========================================="
    echo "安装信息:"
    echo "=========================================="
    echo "服务状态: systemctl status withssl"
    echo "查看日志: journalctl -u withssl -f"
    echo "重启服务: systemctl restart withssl"
    echo "停止服务: systemctl stop withssl"
    echo
    echo "管理面板: https://your-domain/sslcat-panel"
    echo "默认用户名: admin"
    echo "默认密码: admin*9527"
    echo
    echo "配置文件: /etc/sslcat/withssl.conf"
    echo "证书目录: /var/lib/sslcat/certs"
    echo "密钥目录: /var/lib/sslcat/keys"
    echo
    echo "首次登录后请立即修改默认密码！"
    echo "=========================================="
}

# 主函数
main() {
    echo "=========================================="
    echo "SSLcat SSL代理服务器安装脚本"
    echo "=========================================="
    echo
    
    check_root
    detect_os
    install_dependencies
    install_go
    install_certbot
    create_user_and_dirs
    build_withssl
    create_systemd_service
    create_config
    configure_firewall
    start_service
    show_install_info
}

# 运行主函数
main "$@"
