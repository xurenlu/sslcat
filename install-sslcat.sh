#!/bin/bash
set -euo pipefail

# SSLcat 安装脚本
# 用于从 release 包中安装 SSLcat

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

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        log_info "请使用: sudo $0"
        exit 1
    fi
}

# 检查系统类型
check_system() {
    if [[ "$OSTYPE" != "linux-gnu"* && "$OSTYPE" != "darwin"* ]]; then
        log_error "此脚本仅支持 Linux 和 macOS 系统"
        exit 1
    fi
    
    # 检查 systemd（仅 Linux）
    if [[ "$OSTYPE" == "linux-gnu"* ]] && ! command -v systemctl &> /dev/null; then
        log_error "Linux 系统需要 systemd 支持"
        exit 1
    fi
}

# 检查是否已安装
check_existing_installation() {
    # Linux 系统检查 systemd 服务
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if systemctl is-active --quiet sslcat 2>/dev/null; then
            log_warning "检测到 SSLcat 服务正在运行"
            read -p "是否要停止现有服务并重新安装？(y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                log_info "停止现有服务..."
                systemctl stop sslcat || true
            else
                log_info "安装已取消"
                exit 0
            fi
        fi
        
        if [[ -f /opt/sslcat/sslcat ]]; then
            log_warning "检测到现有 SSLcat 安装"
            read -p "是否要覆盖现有安装？(y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "安装已取消"
                exit 0
            fi
        fi
    fi
    
    # macOS 系统检查
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if [[ -f /usr/local/bin/sslcat ]]; then
            log_warning "检测到现有 SSLcat 安装"
            read -p "是否要覆盖现有安装？(y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "安装已取消"
                exit 0
            fi
        fi
    fi
}

# 创建必要的目录
create_directories() {
    log_info "创建必要的目录..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux 系统目录
        mkdir -p /etc/sslcat
        mkdir -p /opt/sslcat/{bin,data,logs}
        mkdir -p /var/log/sslcat
        mkdir -p /var/www
        mkdir -p /home/git
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS 系统目录
        mkdir -p /usr/local/etc/sslcat
        mkdir -p /usr/local/var/sslcat/{data,logs}
        mkdir -p /usr/local/var/www
        mkdir -p /usr/local/var/git
    fi
    
    log_success "目录创建完成"
}

# 创建 git 用户
create_git_user() {
    log_info "创建 git 用户..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux 系统创建 git 用户
        if id "git" &>/dev/null; then
            log_warning "git 用户已存在，跳过创建"
        else
            # 创建 git 用户
            useradd -r -s /bin/bash -d /home/git -m git
            log_success "git 用户创建完成"
        fi
        
        # 设置目录权限
        chown -R git:git /home/git
        chown -R git:git /var/www
        chmod 755 /home/git
        chmod 755 /var/www
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS 系统创建 git 用户
        if id "git" &>/dev/null; then
            log_warning "git 用户已存在，跳过创建"
        else
            # 创建 git 用户
            dscl . -create /Users/git
            dscl . -create /Users/git UserShell /bin/bash
            dscl . -create /Users/git RealName "Git User"
            dscl . -create /Users/git UniqueID 200
            dscl . -create /Users/git PrimaryGroupID 20
            dscl . -create /Users/git NFSHomeDirectory /usr/local/var/git
            dscl . -passwd /Users/git ""
            log_success "git 用户创建完成"
        fi
        
        # 设置目录权限
        chown -R git:staff /usr/local/var/git
        chown -R git:staff /usr/local/var/www
        chmod 755 /usr/local/var/git
        chmod 755 /usr/local/var/www
    fi
    
    log_success "用户权限设置完成"
}

# 安装 SSLcat 二进制文件
install_binary() {
    log_info "安装 SSLcat 二进制文件..."
    
    # 检查当前目录是否有 sslcat 二进制文件
    if [[ ! -f "./sslcat" ]]; then
        log_error "未找到 sslcat 二进制文件"
        log_info "请确保在包含 sslcat 二进制文件的目录中运行此脚本"
        exit 1
    fi
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux 系统安装
        cp sslcat /opt/sslcat/sslcat
        chmod +x /opt/sslcat/sslcat
        chown root:root /opt/sslcat/sslcat
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS 系统安装
        cp sslcat /usr/local/bin/sslcat
        chmod +x /usr/local/bin/sslcat
        chown root:wheel /usr/local/bin/sslcat
    fi
    
    log_success "SSLcat 二进制文件安装完成"
}

# 安装配置文件
install_config() {
    log_info "安装配置文件..."
    
    # 检查是否有配置文件
    if [[ -f "./sslcat.conf" ]]; then
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Linux 系统配置
            # 备份现有配置（如果存在）
            if [[ -f "/etc/sslcat/sslcat.conf" ]]; then
                cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)
                log_info "已备份现有配置文件"
            fi
            
            # 复制新配置
            cp sslcat.conf /etc/sslcat/sslcat.conf
            chmod 644 /etc/sslcat/sslcat.conf
            chown root:root /etc/sslcat/sslcat.conf
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS 系统配置
            # 备份现有配置（如果存在）
            if [[ -f "/usr/local/etc/sslcat/sslcat.conf" ]]; then
                cp /usr/local/etc/sslcat/sslcat.conf /usr/local/etc/sslcat/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)
                log_info "已备份现有配置文件"
            fi
            
            # 复制新配置
            cp sslcat.conf /usr/local/etc/sslcat/sslcat.conf
            chmod 644 /usr/local/etc/sslcat/sslcat.conf
            chown root:wheel /usr/local/etc/sslcat/sslcat.conf
        fi
        
        log_success "配置文件安装完成"
    else
        log_warning "未找到 sslcat.conf 配置文件，将使用默认配置"
        create_default_config
    fi
}

# 创建默认配置
create_default_config() {
    log_info "创建默认配置文件..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux 系统默认配置
        cat > /etc/sslcat/sslcat.conf << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true
  },
  "proxy": {
    "rules": []
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10
  }
}
EOF
        chmod 644 /etc/sslcat/sslcat.conf
        chown root:root /etc/sslcat/sslcat.conf
        log_warning "请编辑 /etc/sslcat/sslcat.conf 配置您的设置"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS 系统默认配置
        cat > /usr/local/etc/sslcat/sslcat.conf << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": true
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": true,
    "auto_renew": false
  },
  "admin": {
    "username": "admin",
    "password_file": "/usr/local/var/sslcat/data/admin.pass",
    "first_run": true
  },
  "proxy": {
    "rules": []
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10
  }
}
EOF
        chmod 644 /usr/local/etc/sslcat/sslcat.conf
        chown root:wheel /usr/local/etc/sslcat/sslcat.conf
        log_warning "请编辑 /usr/local/etc/sslcat/sslcat.conf 配置您的设置"
    fi
    
    log_success "默认配置文件创建完成"
}

# 安装 systemd 服务
install_systemd_service() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "安装 systemd 服务..."
        
        # 检查是否有服务文件
        if [[ -f "./sslcat.service" ]]; then
            cp sslcat.service /etc/systemd/system/sslcat.service
        else
            # 创建默认服务文件
            cat > /etc/systemd/system/sslcat.service << 'EOF'
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf
ExecReload=/bin/kill -HUP $MAINPID
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
ReadWritePaths=/opt/sslcat /etc/sslcat /home/git

[Install]
WantedBy=multi-user.target
EOF
        fi
        
        # 重新加载 systemd
        systemctl daemon-reload
        
        # 启用服务
        systemctl enable sslcat
        
        log_success "systemd 服务安装完成"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "macOS 系统跳过 systemd 服务安装"
        log_info "请手动启动 SSLcat: sslcat --config /usr/local/etc/sslcat/sslcat.conf"
    fi
}

# 设置权限
set_permissions() {
    log_info "设置文件权限..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux 系统权限设置
        chown -R root:root /opt/sslcat
        chown -R root:root /etc/sslcat
        chown -R git:git /home/git
        chown -R git:git /var/www
        chown -R root:root /var/log/sslcat
        chmod +x /opt/sslcat/sslcat
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS 系统权限设置
        chown -R root:wheel /usr/local/bin/sslcat
        chown -R root:wheel /usr/local/etc/sslcat
        chown -R git:staff /usr/local/var/git
        chown -R git:staff /usr/local/var/www
        chown -R root:wheel /usr/local/var/sslcat
        chmod +x /usr/local/bin/sslcat
    fi
    
    log_success "权限设置完成"
}

# 启动服务
start_service() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "启动 SSLcat 服务..."
        
        # 启动服务
        systemctl start sslcat
        
        # 等待服务启动
        sleep 2
        
        # 检查服务状态
        if systemctl is-active --quiet sslcat; then
            log_success "SSLcat 服务启动成功"
        else
            log_error "SSLcat 服务启动失败"
            log_info "查看服务状态: systemctl status sslcat"
            log_info "查看服务日志: journalctl -u sslcat -f"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "macOS 系统跳过自动启动"
        log_info "请手动启动 SSLcat: sslcat --config /usr/local/etc/sslcat/sslcat.conf"
    fi
}

# 显示安装信息
show_installation_info() {
    log_success "SSLcat 安装完成！"
    echo
    echo "📋 安装信息:"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "  - 二进制文件: /opt/sslcat/sslcat"
        echo "  - 配置文件: /etc/sslcat/sslcat.conf"
        echo "  - 服务文件: /etc/systemd/system/sslcat.service"
        echo "  - 日志目录: /var/log/sslcat"
        echo "  - Git 用户: /home/git"
        echo "  - Web 目录: /var/www"
        echo
        echo "🔧 管理命令:"
        echo "  - 启动服务: systemctl start sslcat"
        echo "  - 停止服务: systemctl stop sslcat"
        echo "  - 重启服务: systemctl restart sslcat"
        echo "  - 查看状态: systemctl status sslcat"
        echo "  - 查看日志: journalctl -u sslcat -f"
        echo
        echo "🌐 Web 管理界面:"
        echo "  - 访问地址: http://your-server-ip/sslcat-panel"
        echo "  - 默认用户名: admin"
        echo "  - 默认密码: admin*9527"
        echo
        echo "⚠️  重要提醒:"
        echo "  1. 请编辑 /etc/sslcat/sslcat.conf 配置您的设置"
        echo "  2. 首次登录后请立即修改管理员密码"
        echo "  3. 确保防火墙开放 80 和 443 端口"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  - 二进制文件: /usr/local/bin/sslcat"
        echo "  - 配置文件: /usr/local/etc/sslcat/sslcat.conf"
        echo "  - 日志目录: /usr/local/var/sslcat/logs"
        echo "  - Git 用户: /usr/local/var/git"
        echo "  - Web 目录: /usr/local/var/www"
        echo
        echo "🔧 管理命令:"
        echo "  - 启动服务: sslcat --config /usr/local/etc/sslcat/sslcat.conf"
        echo "  - 停止服务: 按 Ctrl+C 或 kill 进程"
        echo "  - 后台运行: nohup sslcat --config /usr/local/etc/sslcat/sslcat.conf &"
        echo
        echo "🌐 Web 管理界面:"
        echo "  - 访问地址: http://localhost:8080/sslcat-panel"
        echo "  - 默认用户名: admin"
        echo "  - 默认密码: admin*9527"
        echo
        echo "⚠️  重要提醒:"
        echo "  1. 请编辑 /usr/local/etc/sslcat/sslcat.conf 配置您的设置"
        echo "  2. 首次登录后请立即修改管理员密码"
        echo "  3. macOS 版本主要用于开发和测试"
    fi
    echo
}

# 主函数
main() {
    log_info "开始安装 SSLcat..."
    
    # 执行安装步骤
    check_root
    check_system
    check_existing_installation
    create_directories
    create_git_user
    install_binary
    install_config
    install_systemd_service
    set_permissions
    start_service
    show_installation_info
    
    log_success "SSLcat 安装完成！"
}

# 运行主函数
main "$@"
