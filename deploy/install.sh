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

GO_REQUIRED_VERSION="1.27.4"

# 逐段比较稳定版；缺省补丁号按 0 处理，拒绝 rc/beta/devel。
go_version_at_least() {
    local current=${1#go} minimum=${2#go}
    local pattern='^([0-9]+)\.([0-9]+)(\.([0-9]+))?$'
    local -a current_parts minimum_parts
    local index

    [[ $current =~ $pattern ]] || return 1
    current_parts=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[4]:-0}")
    [[ $minimum =~ $pattern ]] || return 1
    minimum_parts=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[4]:-0}")
    for index in 0 1 2; do
        if (( 10#${current_parts[index]} > 10#${minimum_parts[index]} )); then
            return 0
        elif (( 10#${current_parts[index]} < 10#${minimum_parts[index]} )); then
            return 1
        fi
    done
    return 0
}

# 不仅检查版本，还检查标准库源码和当前平台的编译、链接工具。
go_toolchain_usable() {
    local go_root=$1 version_output current_go_version tool_dir
    [[ -x "$go_root/bin/go" && -d "$go_root/src/runtime" ]] || return 1
    version_output=$(env GOROOT="$go_root" GOTOOLCHAIN=local "$go_root/bin/go" version) || return 1
    read -r _ _ current_go_version _ <<< "$version_output"
    go_version_at_least "$current_go_version" "$GO_REQUIRED_VERSION" || return 1
    tool_dir=$(env GOROOT="$go_root" GOTOOLCHAIN=local "$go_root/bin/go" env GOTOOLDIR) || return 1
    [[ "$tool_dir" == "$go_root"/pkg/tool/* && -x "$tool_dir/compile" && -x "$tool_dir/link" ]]
}

# 每次入口都重新选择；忽略继承的旧 GOROOT，避免版本探测触发自动下载。
select_go_toolchain() {
    local system_go go_root version_output current_go_version
    system_go=$(command -v go) || system_go=""
    if [[ -n "$system_go" ]] && version_output=$(env -u GOROOT GOTOOLCHAIN=local "$system_go" version); then
        read -r _ _ current_go_version _ <<< "$version_output"
        if go_version_at_least "$current_go_version" "$GO_REQUIRED_VERSION" &&
            go_root=$(env -u GOROOT GOTOOLCHAIN=local "$system_go" env GOROOT) &&
            go_toolchain_usable "$go_root"; then
            export GOROOT="$go_root"
            export PATH="$GOROOT/bin:$PATH" GOTOOLCHAIN=local
            hash -r
            return 0
        fi
    fi
    go_root="/opt/sslcat-toolchains/go${GO_REQUIRED_VERSION}"
    if go_toolchain_usable "$go_root"; then
        export GOROOT="$go_root"
        export PATH="$GOROOT/bin:$PATH" GOTOOLCHAIN=local
        hash -r
        return 0
    fi
    return 1
}

# 子 shell 隔离 trap；只清理本次 mktemp 创建的内容，未知旧目录始终保留。
install_go_toolchain() (
    local go_install_dir=$1 go_parent go_arch go_sha256 go_archive
    # Bash 3.2 显式 exit 会先释放函数 local；清理状态由隔离子 shell 持有。
    sslcat_go_install_target=$go_install_dir
    sslcat_go_install_staging="" sslcat_go_install_backup=""
    go_parent=$(dirname "$go_install_dir")

    cleanup_go_install() {
        local exit_status=$?
        trap - EXIT HUP INT TERM
        if [[ -n "$sslcat_go_install_backup" && ( -e "$sslcat_go_install_backup/previous" || -L "$sslcat_go_install_backup/previous" ) ]]; then
            if [[ ! -e "$sslcat_go_install_target" && ! -L "$sslcat_go_install_target" ]]; then
                if ! mv -T -- "$sslcat_go_install_backup/previous" "$sslcat_go_install_target"; then
                    printf '恢复原Go目录失败，原内容保留于: %s\n' "$sslcat_go_install_backup/previous" >&2
                    exit_status=1
                fi
            fi
        fi
        if [[ -n "$sslcat_go_install_staging" ]]; then
            rm -rf -- "$sslcat_go_install_staging" || exit_status=1
        fi
        if [[ -n "$sslcat_go_install_backup" ]]; then
            if [[ -e "$sslcat_go_install_backup/previous" || -L "$sslcat_go_install_backup/previous" ]]; then
                printf '原Go目录备份保留于: %s\n' "$sslcat_go_install_backup/previous" >&2
            else
                rmdir -- "$sslcat_go_install_backup" || exit_status=1
            fi
        fi
        exit "$exit_status"
    }
    trap cleanup_go_install EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    case $(uname -m) in
        x86_64|amd64)
            go_arch=amd64
            go_sha256=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
            ;;
        aarch64|arm64)
            go_arch=arm64
            go_sha256=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
            ;;
        *)
            printf 'Go %s安装不支持架构: %s\n' "$GO_REQUIRED_VERSION" "$(uname -m)" >&2
            exit 1
            ;;
    esac
    go_archive="go${GO_REQUIRED_VERSION}.linux-${go_arch}.tar.gz"
    mkdir -p "$go_parent" || exit 1
    sslcat_go_install_staging=$(mktemp -d "$go_parent/.go${GO_REQUIRED_VERSION}.staging.XXXXXX") || exit 1
    mkdir "$sslcat_go_install_staging/download" "$sslcat_go_install_staging/toolchain" || exit 1
    printf '下载Go %s (%s)...\n' "$GO_REQUIRED_VERSION" "$go_arch"
    wget -q --timeout=30 --tries=3 -O "$sslcat_go_install_staging/download/$go_archive" "https://go.dev/dl/$go_archive" || {
        printf 'Go下载失败: %s\n' "$go_archive" >&2
        exit 1
    }
    if ! printf '%s  %s\n' "$go_sha256" "$sslcat_go_install_staging/download/$go_archive" | sha256sum --check --status; then
        printf 'Go归档SHA-256校验失败: %s\n' "$go_archive" >&2
        exit 1
    fi
    tar -C "$sslcat_go_install_staging/toolchain" --strip-components=1 -xzf "$sslcat_go_install_staging/download/$go_archive" || {
        printf 'Go归档解压失败: %s\n' "$go_archive" >&2
        exit 1
    }
    go_toolchain_usable "$sslcat_go_install_staging/toolchain" || {
        printf '解压后的Go工具链不完整或不可用: %s\n' "$go_archive" >&2
        exit 1
    }
    # 另一个安装进程可能已准备好可用缓存。
    if go_toolchain_usable "$go_install_dir"; then
        exit 0
    fi
    if [[ -e "$go_install_dir" || -L "$go_install_dir" ]]; then
        sslcat_go_install_backup=$(mktemp -d "$go_parent/.go${GO_REQUIRED_VERSION}.backup.XXXXXX") || exit 1
        mv -T -- "$go_install_dir" "$sslcat_go_install_backup/previous" || {
            printf '备份原Go目录失败: %s\n' "$go_install_dir" >&2
            exit 1
        }
    fi
    mv -T -- "$sslcat_go_install_staging/toolchain" "$go_install_dir" || {
        printf '发布Go工具链失败: %s\n' "$go_install_dir" >&2
        exit 1
    }
)

# 工具链使用应用专用目录，仅调整当前安装会话的环境。
install_go() {
    local go_install_dir="/opt/sslcat-toolchains/go${GO_REQUIRED_VERSION}"
    log_info "检查Go环境..."
    if ! select_go_toolchain; then
        install_go_toolchain "$go_install_dir" || return 1
        select_go_toolchain || return 1
    fi
    mkdir -p /opt/go/{bin,src,pkg} || return 1
    export GOPATH=/opt/go
    export GOBIN=$GOPATH/bin
    log_success "Go已就绪: $GOROOT"
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
    mkdir -p /opt/sslcat/{certs,keys,logs}
    mkdir -p /opt/sslcat
    
    # 设置权限
    chown -R withssl:withssl /opt/sslcat
    chmod 755 /etc/sslcat
    chmod 700 /opt/sslcat
    
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

# Go 运行时内存管理优化 - 优先控制长期运行后的 RSS 高水位残留
Environment="GOMEMLIMIT=1280MiB"
Environment="GOGC=200"
Environment="GODEBUG=madvdontneed=1"

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
  cert_dir: "/opt/sslcat/certs"
  key_dir: "/opt/sslcat/keys"
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
  block_file: "/opt/sslcat/withssl.block"
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
    # 获取公网IP
    PUBLIC_IP=$(curl -s https://ip4.dev/myip | tr -d '\n' | xargs)
    echo "管理面板: http://$PUBLIC_IP:80/sslcat-panel/ 或 https://<你的域名>/sslcat-panel/"
    echo "默认用户名: admin"
    echo "默认密码: admin*9527"
    echo
    echo "配置文件: /etc/sslcat/withssl.conf"
    echo "证书目录: /opt/sslcat/certs"
    echo "密钥目录: /opt/sslcat/keys"
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
