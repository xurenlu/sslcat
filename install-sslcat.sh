#!/bin/bash
set -euo pipefail

# SSLcat 安装脚本 / SSLcat Install Script
# 用于从 release 包中安装 SSLcat / Install SSLcat from release package

# =============================================================================
# 语言检测与选择 / Locale Detection & Language Selection
# =============================================================================

# 根据终端环境变量检测默认语言 (LANG, LC_ALL, LC_MESSAGES)
# Detect default language from terminal (LANG, LC_ALL, LC_MESSAGES)
detect_locale() {
    local lang_var="${LANG:-}${LC_ALL:-}${LC_MESSAGES:-}"
    if [[ -z "$lang_var" ]]; then
        echo "en"
        return
    fi
    # zh_CN, zh_TW, zh-Hans, zh-Hant 等均识别为中文
    if [[ "$lang_var" =~ ^[zZ][hH] ]]; then
        echo "zh"
    else
        echo "en"
    fi
}

# 显示语言选择菜单，5 秒超时，默认使用检测到的语言
# Show language selection, 5s timeout, default to detected locale
select_language() {
    local default_lang
    default_lang=$(detect_locale)
    
    echo ""
    echo "Select language / 选择语言:"
    echo "  [1] 中文 (Chinese)"
    echo "  [2] English"
    echo ""
    if [[ "$default_lang" == "zh" ]]; then
        printf "请选择 (1/2, 默认 1, 5秒后自动使用中文): "
    else
        printf "Choose (1/2, default 2, 5s timeout → English): "
    fi
    
    LANG_CHOICE=""
    read -r -n 1 -t 5 LANG_CHOICE 2>/dev/null || true
    echo ""
    
    if [[ "$LANG_CHOICE" == "1" ]]; then
        INSTALL_LANG="zh"
    elif [[ "$LANG_CHOICE" == "2" ]]; then
        INSTALL_LANG="en"
    else
        INSTALL_LANG="$default_lang"
    fi
}

# =============================================================================
# 多语言消息 / i18n Messages (bash 3.2 compatible, no associative arrays)
# =============================================================================

init_messages() {
    local lang="$1"
    
    if [[ "$lang" == "zh" ]]; then
        MSG_need_root="此脚本需要 root 权限运行"
        MSG_use_sudo="请使用: sudo $0"
        MSG_unsupported_os="此脚本仅支持 Linux 和 macOS 系统"
        MSG_need_systemd="Linux 系统需要 systemd 支持"
        MSG_service_running="检测到 SSLcat 服务正在运行"
        MSG_stop_and_reinstall="是否要停止现有服务并重新安装？选择 y 将停止服务并继续安装，选择 N 将取消安装"
        MSG_stopping_service="停止现有服务..."
        MSG_install_cancelled="安装已取消"
        MSG_existing_install="检测到现有 SSLcat 安装"
        MSG_overwrite_install="是否要覆盖现有安装？选择 y 将覆盖现有安装，选择 N 将取消安装"
        MSG_timeout_auto="超时 %s 秒后将自动选择: %s"
        MSG_choose_yn="请选择 (y/N): "
        MSG_timeout_choice="超时，自动选择: %s"
        MSG_creating_dirs="创建必要的目录..."
        MSG_dirs_done="目录创建完成"
        MSG_creating_git_user="创建 git 用户..."
        MSG_git_user_exists="git 用户已存在，跳过创建"
        MSG_git_user_created="git 用户创建完成"
        MSG_perms_done="用户权限设置完成"
        MSG_installing_binary="安装 SSLcat 二进制文件..."
        MSG_binary_not_found="未找到 sslcat 二进制文件"
        MSG_run_in_dir="请确保在包含 sslcat 二进制文件的目录中运行此脚本"
        MSG_binary_done="SSLcat 二进制文件安装完成"
        MSG_installing_hook="安装 sslcat-git-hook..."
        MSG_hook_not_found="未找到 sslcat-git-hook 脚本，跳过安装"
        MSG_hook_done="sslcat-git-hook 安装完成"
        MSG_creating_hook_config="创建 git hook 配置文件..."
        MSG_hook_config_done="git hook 配置文件创建完成: %s"
        MSG_config_diff="配置文件差异对比："
        MSG_config_new="--- 新配置文件"
        MSG_config_old="+++ 现有配置文件"
        MSG_more_diff="... (更多差异，请查看完整对比)"
        MSG_installing_config="安装配置文件..."
        MSG_config_same="配置文件内容相同，跳过覆盖"
        MSG_config_installed="配置文件安装完成（无需更新）"
        MSG_config_diff_warn="检测到现有配置文件与安装包中的配置文件不同"
        MSG_overwrite_config="是否要覆盖现有配置文件？选择 y 将覆盖现有配置，选择 N 将保留现有配置。建议：如果现有配置已正常工作，建议选择 N 保留现有配置"
        MSG_keep_config="保留现有配置文件，跳过配置文件安装"
        MSG_manual_update="如需手动更新配置，请参考上述差异对比"
        MSG_config_backed_up="已备份现有配置文件到: %s"
        MSG_restore_config="如需恢复原配置，请运行: cp %s %s"
        MSG_config_done="配置文件安装完成"
        MSG_no_config="未找到 sslcat.conf 配置文件，将使用默认配置"
        MSG_creating_default_config="创建默认配置文件..."
        MSG_edit_config_linux="请编辑 /etc/sslcat/sslcat.conf 配置您的设置"
        MSG_edit_config_macos="请编辑 /usr/local/etc/sslcat/sslcat.conf 配置您的设置"
        MSG_default_config_done="默认配置文件创建完成"
        MSG_installing_systemd="安装 systemd 服务..."
        MSG_systemd_done="systemd 服务安装完成"
        MSG_macos_skip_systemd="macOS 系统跳过 systemd 服务安装"
        MSG_manual_start_macos="请手动启动 SSLcat: sslcat --config /usr/local/etc/sslcat/sslcat.conf"
        MSG_setting_perms="设置文件权限..."
        MSG_perms_done2="权限设置完成"
        MSG_starting_service="启动 SSLcat 服务..."
        MSG_service_started="SSLcat 服务启动成功"
        MSG_service_failed="SSLcat 服务启动失败"
        MSG_check_status="查看服务状态: systemctl status sslcat"
        MSG_check_logs="查看服务日志: journalctl -u sslcat -f"
        MSG_macos_skip_start="macOS 系统跳过自动启动"
        MSG_install_complete="SSLcat 安装完成！"
        MSG_install_info="安装信息:"
        MSG_binary="二进制文件"
        MSG_config="配置文件"
        MSG_service_file="服务文件"
        MSG_git_hook="Git Hook"
        MSG_git_hook_config="Git Hook 配置"
        MSG_log_dir="日志目录"
        MSG_git_user="Git 用户"
        MSG_web_dir="Web 目录"
        MSG_management="管理命令:"
        MSG_start="启动服务"
        MSG_stop="停止服务"
        MSG_restart="重启服务"
        MSG_status="查看状态"
        MSG_logs="查看日志"
        MSG_web_panel="Web 管理界面:"
        MSG_access_url="访问地址"
        MSG_default_user="默认用户名"
        MSG_default_pass="默认密码"
        MSG_important="重要提醒:"
        MSG_reminder_1="请编辑 %s 配置您的设置"
        MSG_reminder_2="首次登录后请立即修改管理员密码"
        MSG_reminder_3="确保防火墙开放 80 和 443 端口"
        MSG_reminder_4="Git Hook 已安装，支持 Dokku 风格的 git push 部署"
        MSG_reminder_5="在 authorized_keys 中使用: command=\"/usr/local/bin/sslcat-git-hook KEY_NAME\""
        MSG_macos_reminder_3="macOS 版本主要用于开发和测试"
        MSG_start_sslcat="启动服务: systemctl start sslcat"
        MSG_stop_sslcat="停止服务: systemctl stop sslcat"
        MSG_restart_sslcat="重启服务: systemctl restart sslcat"
        MSG_status_sslcat="查看状态: systemctl status sslcat"
        MSG_logs_sslcat="查看日志: journalctl -u sslcat -f"
        MSG_macos_stop="停止服务: 按 Ctrl+C 或 kill 进程"
        MSG_macos_background="后台运行: nohup sslcat --config /usr/local/etc/sslcat/sslcat.conf &"
        MSG_start_install="开始安装 SSLcat..."
    else
        MSG_need_root="This script requires root privileges"
        MSG_use_sudo="Please use: sudo $0"
        MSG_unsupported_os="This script only supports Linux and macOS"
        MSG_need_systemd="Linux requires systemd support"
        MSG_service_running="SSLcat service is running"
        MSG_stop_and_reinstall="Stop existing service and reinstall? y=stop and continue, N=cancel"
        MSG_stopping_service="Stopping existing service..."
        MSG_install_cancelled="Installation cancelled"
        MSG_existing_install="Existing SSLcat installation detected"
        MSG_overwrite_install="Overwrite existing installation? y=overwrite, N=cancel"
        MSG_timeout_auto="Auto-select after %s seconds: %s"
        MSG_choose_yn="Choose (y/N): "
        MSG_timeout_choice="Timeout, auto-selected: %s"
        MSG_creating_dirs="Creating directories..."
        MSG_dirs_done="Directories created"
        MSG_creating_git_user="Creating git user..."
        MSG_git_user_exists="git user already exists, skipping"
        MSG_git_user_created="git user created"
        MSG_perms_done="User permissions set"
        MSG_installing_binary="Installing SSLcat binary..."
        MSG_binary_not_found="sslcat binary not found"
        MSG_run_in_dir="Please run this script from the directory containing the sslcat binary"
        MSG_binary_done="SSLcat binary installed"
        MSG_installing_hook="Installing sslcat-git-hook..."
        MSG_hook_not_found="sslcat-git-hook not found, skipping"
        MSG_hook_done="sslcat-git-hook installed"
        MSG_creating_hook_config="Creating git hook config..."
        MSG_hook_config_done="git hook config created: %s"
        MSG_config_diff="Config file diff:"
        MSG_config_new="--- New config"
        MSG_config_old="+++ Existing config"
        MSG_more_diff="... (more diff, see full comparison)"
        MSG_installing_config="Installing config file..."
        MSG_config_same="Config unchanged, skipping overwrite"
        MSG_config_installed="Config installed (no update needed)"
        MSG_config_diff_warn="Existing config differs from package"
        MSG_overwrite_config="Overwrite existing config? y=overwrite, N=keep. Recommend N if existing config works."
        MSG_keep_config="Keeping existing config, skipping"
        MSG_manual_update="Refer to diff above for manual update"
        MSG_config_backed_up="Config backed up to: %s"
        MSG_restore_config="To restore: cp %s %s"
        MSG_config_done="Config installed"
        MSG_no_config="sslcat.conf not found, using default config"
        MSG_creating_default_config="Creating default config..."
        MSG_edit_config_linux="Edit /etc/sslcat/sslcat.conf to configure"
        MSG_edit_config_macos="Edit /usr/local/etc/sslcat/sslcat.conf to configure"
        MSG_default_config_done="Default config created"
        MSG_installing_systemd="Installing systemd service..."
        MSG_systemd_done="systemd service installed"
        MSG_macos_skip_systemd="macOS: skipping systemd installation"
        MSG_manual_start_macos="Start manually: sslcat --config /usr/local/etc/sslcat/sslcat.conf"
        MSG_setting_perms="Setting permissions..."
        MSG_perms_done2="Permissions set"
        MSG_starting_service="Starting SSLcat service..."
        MSG_service_started="SSLcat service started"
        MSG_service_failed="SSLcat service failed to start"
        MSG_check_status="Check status: systemctl status sslcat"
        MSG_check_logs="Check logs: journalctl -u sslcat -f"
        MSG_macos_skip_start="macOS: skipping auto-start"
        MSG_install_complete="SSLcat installation complete!"
        MSG_install_info="Installation info:"
        MSG_binary="Binary"
        MSG_config="Config"
        MSG_service_file="Service file"
        MSG_git_hook="Git Hook"
        MSG_git_hook_config="Git Hook config"
        MSG_log_dir="Log dir"
        MSG_git_user="Git user"
        MSG_web_dir="Web dir"
        MSG_management="Management:"
        MSG_start="Start"
        MSG_stop="Stop"
        MSG_restart="Restart"
        MSG_status="Status"
        MSG_logs="Logs"
        MSG_web_panel="Web panel:"
        MSG_access_url="URL"
        MSG_default_user="Default user"
        MSG_default_pass="Default password"
        MSG_important="Important:"
        MSG_reminder_1="Edit %s to configure"
        MSG_reminder_2="Change admin password after first login"
        MSG_reminder_3="Open firewall ports 80 and 443"
        MSG_reminder_4="Git Hook installed for Dokku-style git push deploy"
        MSG_reminder_5="In authorized_keys: command=\"/usr/local/bin/sslcat-git-hook KEY_NAME\""
        MSG_macos_reminder_3="macOS build is for dev/test"
        MSG_start_sslcat="Start: systemctl start sslcat"
        MSG_stop_sslcat="Stop: systemctl stop sslcat"
        MSG_restart_sslcat="Restart: systemctl restart sslcat"
        MSG_status_sslcat="Status: systemctl status sslcat"
        MSG_logs_sslcat="Logs: journalctl -u sslcat -f"
        MSG_macos_stop="Stop: Ctrl+C or kill process"
        MSG_macos_background="Background: nohup sslcat --config /usr/local/etc/sslcat/sslcat.conf &"
        MSG_start_install="Starting SSLcat installation..."
    fi
}

# 获取本地化消息 (支持 %s 占位符)
msg() {
    local key="$1"
    shift
    local val
    eval "val=\"\${MSG_${key}}\""
    if [[ $# -gt 0 ]]; then
        printf "$val" "$@"
    else
        echo -n "$val"
    fi
}

# =============================================================================
# 颜色定义 / Colors
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# 日志函数 / Logging
# =============================================================================

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

# =============================================================================
# 带超时的用户输入 (支持多语言)
# =============================================================================

read_with_timeout() {
    local prompt="$1"
    local timeout="$2"
    local default="$3"
    
    echo -e "${YELLOW}${prompt}${NC}"
    if [[ -n "$default" ]]; then
        local timeout_msg
        timeout_msg=$(msg timeout_auto "$timeout" "$default")
        echo -e "${YELLOW}${timeout_msg}${NC}"
    fi
    
    local choose_prompt
    choose_prompt=$(msg choose_yn)
    read -p "$choose_prompt" -n 1 -r -t "$timeout"
    echo
    
    if [[ -z "$REPLY" ]]; then
        if [[ "$default" == "y" || "$default" == "Y" ]]; then
            REPLY="y"
        else
            REPLY="N"
        fi
        local timeout_choice
        timeout_choice=$(msg timeout_choice "$REPLY")
        echo -e "${BLUE}${timeout_choice}${NC}"
    fi
}

# =============================================================================
# 检查是否为 root
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "$(msg need_root)"
        log_info "$(msg use_sudo)"
        exit 1
    fi
}

# =============================================================================
# 检查系统类型
# =============================================================================

check_system() {
    if [[ "$OSTYPE" != "linux-gnu"* && "$OSTYPE" != "darwin"* ]]; then
        log_error "$(msg unsupported_os)"
        exit 1
    fi
    
    if [[ "$OSTYPE" == "linux-gnu"* ]] && ! command -v systemctl &> /dev/null; then
        log_error "$(msg need_systemd)"
        exit 1
    fi
}

# =============================================================================
# 检查是否已安装
# =============================================================================

check_existing_installation() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if systemctl is-active --quiet sslcat 2>/dev/null; then
            log_warning "$(msg service_running)"
            read_with_timeout "$(msg stop_and_reinstall)" 30 "N"
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                log_info "$(msg stopping_service)"
                systemctl stop sslcat || true
            else
                log_info "$(msg install_cancelled)"
                exit 0
            fi
        fi
        
        if [[ -f /opt/sslcat/sslcat ]]; then
            log_warning "$(msg existing_install)"
            read_with_timeout "$(msg overwrite_install)" 30 "N"
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "$(msg install_cancelled)"
                exit 0
            fi
        fi
    fi
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if [[ -f /usr/local/bin/sslcat ]]; then
            log_warning "$(msg existing_install)"
            read_with_timeout "$(msg overwrite_install)" 30 "N"
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "$(msg install_cancelled)"
                exit 0
            fi
        fi
    fi
}

# =============================================================================
# 创建目录
# =============================================================================

create_directories() {
    log_info "$(msg creating_dirs)"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        mkdir -p /etc/sslcat
        mkdir -p /opt/sslcat/{bin,data,logs,scripts}
        mkdir -p /opt/sslcat/data/{certs,keys,cache/static,runners/git,upstream-cache}
        mkdir -p /var/log/sslcat
        mkdir -p /var/lib/sslcat
        mkdir -p /var/www
        mkdir -p /home/git
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        mkdir -p /usr/local/etc/sslcat
        mkdir -p /usr/local/var/sslcat/{data,logs}
        mkdir -p /usr/local/var/www
        mkdir -p /usr/local/var/git
    fi
    
    log_success "$(msg dirs_done)"
}

# =============================================================================
# 创建 git 用户
# =============================================================================

create_git_user() {
    log_info "$(msg creating_git_user)"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if id "git" &>/dev/null; then
            log_warning "$(msg git_user_exists)"
        else
            useradd -r -s /bin/bash -d /home/git -m git
            log_success "$(msg git_user_created)"
        fi
        
        chown -R git:git /home/git
        chown -R git:git /var/www
        chmod 755 /home/git
        chmod 755 /var/www
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if id "git" &>/dev/null; then
            log_warning "$(msg git_user_exists)"
        else
            dscl . -create /Users/git
            dscl . -create /Users/git UserShell /bin/bash
            dscl . -create /Users/git RealName "Git User"
            dscl . -create /Users/git UniqueID 200
            dscl . -create /Users/git PrimaryGroupID 20
            dscl . -create /Users/git NFSHomeDirectory /usr/local/var/git
            dscl . -passwd /Users/git ""
            log_success "$(msg git_user_created)"
        fi
        
        chown -R git:staff /usr/local/var/git
        chown -R git:staff /usr/local/var/www
        chmod 755 /usr/local/var/git
        chmod 755 /usr/local/var/www
    fi
    
    log_success "$(msg perms_done)"
}

# =============================================================================
# 安装二进制文件
# =============================================================================

install_binary() {
    log_info "$(msg installing_binary)"
    
    if [[ ! -f "./sslcat" ]]; then
        log_error "$(msg binary_not_found)"
        log_info "$(msg run_in_dir)"
        exit 1
    fi
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        cp sslcat /opt/sslcat/sslcat
        chmod +x /opt/sslcat/sslcat
        chown root:root /opt/sslcat/sslcat
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        cp sslcat /usr/local/bin/sslcat
        chmod +x /usr/local/bin/sslcat
        chown root:wheel /usr/local/bin/sslcat
    fi
    
    log_success "$(msg binary_done)"
}

# =============================================================================
# 安装 sslcat-git-hook
# =============================================================================

install_git_hook() {
    log_info "$(msg installing_hook)"
    
    if [[ ! -f "./sslcat-git-hook" ]] && [[ ! -f "./scripts/sslcat-git-hook" ]]; then
        log_warning "$(msg hook_not_found)"
        return 0
    fi
    
    local hook_script=""
    if [[ -f "./sslcat-git-hook" ]]; then
        hook_script="./sslcat-git-hook"
    elif [[ -f "./scripts/sslcat-git-hook" ]]; then
        hook_script="./scripts/sslcat-git-hook"
    fi
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        cp "$hook_script" /usr/local/bin/sslcat-git-hook
        chmod +x /usr/local/bin/sslcat-git-hook
        chown root:root /usr/local/bin/sslcat-git-hook
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        cp "$hook_script" /usr/local/bin/sslcat-git-hook
        chmod +x /usr/local/bin/sslcat-git-hook
        chown root:wheel /usr/local/bin/sslcat-git-hook
    fi
    
    create_git_hook_config
    
    log_success "$(msg hook_done)"
}

# =============================================================================
# 创建 git hook 配置文件
# =============================================================================

create_git_hook_config() {
    log_info "$(msg creating_hook_config)"
    
    local admin_prefix="/sslcat-panel"
    local server_port="443"
    local repos_dir="/opt/sslcat/data/runners/git"
    
    local config_file=""
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        config_file="/etc/sslcat/sslcat.conf"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        config_file="/usr/local/etc/sslcat/sslcat.conf"
    fi
    
    if [[ -f "$config_file" ]]; then
        local detected_port detected_prefix detected_repos
        detected_port=$(grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' "$config_file" | grep -o '[0-9]*' | head -1 || echo "")
        detected_prefix=$(grep -o '"admin_prefix"[[:space:]]*:[[:space:]]*"[^"]*"' "$config_file" | sed 's/.*"\([^"]*\)".*/\1/' | head -1 || echo "")
        detected_repos=$(grep -o '"repos_dir"[[:space:]]*:[[:space:]]*"[^"]*"' "$config_file" | sed 's/.*"\([^"]*\)".*/\1/' | head -1 || echo "")
        
        [[ -n "$detected_port" ]] && server_port="$detected_port"
        [[ -n "$detected_prefix" ]] && admin_prefix="$detected_prefix"
        [[ -n "$detected_repos" ]] && repos_dir="$detected_repos"
    fi
    
    local api_url
    if [[ "$server_port" == "443" ]]; then
        api_url="http://localhost:80${admin_prefix}"
    else
        api_url="http://localhost:${server_port}${admin_prefix}"
    fi
    
    local hook_config_file=""
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        hook_config_file="/etc/sslcat/git-hook.conf"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        hook_config_file="/usr/local/etc/sslcat/git-hook.conf"
    fi
    
    cat > "$hook_config_file" << EOF
# SSLcat Git Hook 配置文件 / SSLcat Git Hook Config
# Generated: $(date)

export SSLCAT_API_URL="$api_url"
export SSLCAT_REPOS_DIR="$repos_dir"
EOF
    
    chmod 644 "$hook_config_file"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        chown root:root "$hook_config_file"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        chown root:wheel "$hook_config_file"
    fi
    
    log_success "$(msg hook_config_done "$hook_config_file")"
}

# =============================================================================
# 配置文件差异检查
# =============================================================================

check_config_difference() {
    local new_config="$1"
    local existing_config="$2"
    
    if [[ ! -f "$existing_config" ]]; then
        return 1
    fi
    
    if diff -q -I '^[[:space:]]*#' -I '^[[:space:]]*$' "$new_config" "$existing_config" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

show_config_diff() {
    local new_config="$1"
    local existing_config="$2"
    
    log_info "$(msg config_diff)"
    echo "$(msg config_new)"
    echo "$(msg config_old)"
    diff -u "$existing_config" "$new_config" | head -20 || true
    if [[ $(diff -u "$existing_config" "$new_config" | wc -l) -gt 20 ]]; then
        echo "$(msg more_diff)"
    fi
}

# =============================================================================
# 安装配置文件
# =============================================================================

install_config() {
    log_info "$(msg installing_config)"
    
    if [[ -f "./sslcat.conf" ]]; then
        local target_config=""
        local backup_config=""
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            target_config="/etc/sslcat/sslcat.conf"
            backup_config="/etc/sslcat/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            target_config="/usr/local/etc/sslcat/sslcat.conf"
            backup_config="/usr/local/etc/sslcat/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)"
        fi
        
        if check_config_difference "./sslcat.conf" "$target_config"; then
            log_info "$(msg config_same)"
            log_success "$(msg config_installed)"
            return 0
        fi
        
        if [[ -f "$target_config" ]]; then
            log_warning "$(msg config_diff_warn)"
            show_config_diff "./sslcat.conf" "$target_config"
            echo
            read_with_timeout "$(msg overwrite_config)" 45 "N"
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "$(msg keep_config)"
                log_info "$(msg manual_update)"
                return 0
            fi
            
            cp "$target_config" "$backup_config"
            log_info "$(msg config_backed_up "$backup_config")"
            log_info "$(msg restore_config "$backup_config" "$target_config")"
        fi
        
        cp sslcat.conf "$target_config"
        chmod 644 "$target_config"
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            chown root:root "$target_config"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            chown root:wheel "$target_config"
        fi
        
        log_success "$(msg config_done)"
    else
        log_warning "$(msg no_config)"
        create_default_config
    fi
}

# =============================================================================
# 创建默认配置
# =============================================================================

create_default_config() {
    log_info "$(msg creating_default_config)"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        cat > /etc/sslcat/sslcat.conf << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false,
    "data_dir": "./data",
    "access_log_enabled": false,
    "access_log_path": "./logs/access.log",
    "access_log_max_size": 104857600,
    "access_log_max_files": 10
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true,
    "cert_dir": "./data/certs",
    "key_dir": "./data/keys"
  },
  "admin": {
    "username": "admin",
    "password_file": "./data/admin.pass",
    "totp_secret_file": "./data/admin.totp",
    "first_run": true
  },
  "proxy": {
    "rules": []
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10,
    "block_file": "./data/sslcat.block"
  },
  "cdn_cache": {
    "enabled": false,
    "cache_dir": "./data/cache/static"
  },
  "upstream_cache": {
    "enabled": true,
    "cache_dir": "./data/upstream-cache"
  },
  "runners": {
    "git": {
      "enabled": false,
      "repos_dir": "./data/runners/git"
    }
  }
}
EOF
        chmod 644 /etc/sslcat/sslcat.conf
        chown root:root /etc/sslcat/sslcat.conf
        log_warning "$(msg edit_config_linux)"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
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
        log_warning "$(msg edit_config_macos)"
    fi
    
    log_success "$(msg default_config_done)"
}

# =============================================================================
# 安装 systemd 服务
# =============================================================================

install_systemd_service() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "$(msg installing_systemd)"
        
        if [[ -f "./sslcat.service" ]]; then
            cp sslcat.service /etc/systemd/system/sslcat.service
        else
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

Environment="GOMEMLIMIT=1280MiB"
Environment="GOGC=200"
Environment="GODEBUG=madvdontneed=1"

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/opt/sslcat /etc/sslcat /home/git /var/lib/sslcat

[Install]
WantedBy=multi-user.target
EOF
        fi
        
        systemctl daemon-reload
        systemctl enable sslcat
        
        log_success "$(msg systemd_done)"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "$(msg macos_skip_systemd)"
        log_info "$(msg manual_start_macos)"
    fi
}

# =============================================================================
# 设置权限
# =============================================================================

set_permissions() {
    log_info "$(msg setting_perms)"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        chown -R root:root /opt/sslcat
        chown -R root:root /etc/sslcat
        chown -R git:git /home/git
        chown -R git:git /var/www
        chown -R root:root /var/log/sslcat
        chmod +x /opt/sslcat/sslcat
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        chown -R root:wheel /usr/local/bin/sslcat
        chown -R root:wheel /usr/local/etc/sslcat
        chown -R git:staff /usr/local/var/git
        chown -R git:staff /usr/local/var/www
        chown -R root:wheel /usr/local/var/sslcat
        chmod +x /usr/local/bin/sslcat
    fi
    
    log_success "$(msg perms_done2)"
}

# =============================================================================
# 启动服务
# =============================================================================

start_service() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log_info "$(msg starting_service)"
        
        systemctl start sslcat
        sleep 2
        
        if systemctl is-active --quiet sslcat; then
            log_success "$(msg service_started)"
        else
            log_error "$(msg service_failed)"
            log_info "$(msg check_status)"
            log_info "$(msg check_logs)"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log_info "$(msg macos_skip_start)"
        log_info "$(msg manual_start_macos)"
    fi
}

# =============================================================================
# 显示安装信息
# =============================================================================

show_installation_info() {
    log_success "$(msg install_complete)"
    echo
    echo "📋 $(msg install_info)"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "  - $(msg binary): /opt/sslcat/sslcat"
        echo "  - $(msg config): /etc/sslcat/sslcat.conf"
        echo "  - $(msg service_file): /etc/systemd/system/sslcat.service"
        echo "  - $(msg git_hook): /usr/local/bin/sslcat-git-hook"
        echo "  - $(msg git_hook_config): /etc/sslcat/git-hook.conf"
        echo "  - $(msg log_dir): /var/log/sslcat"
        echo "  - $(msg git_user): /home/git"
        echo "  - $(msg web_dir): /var/www"
        echo
        echo "🔧 $(msg management)"
        echo "  - $(msg start_sslcat)"
        echo "  - $(msg stop_sslcat)"
        echo "  - $(msg restart_sslcat)"
        echo "  - $(msg status_sslcat)"
        echo "  - $(msg logs_sslcat)"
        echo
        echo "🌐 $(msg web_panel)"
        echo "  - $(msg access_url): http://your-server-ip/sslcat-panel"
        echo "  - $(msg default_user): admin"
        echo "  - $(msg default_pass): admin*9527"
        echo
        echo "⚠️  $(msg important)"
        echo "  1. $(msg reminder_1 "/etc/sslcat/sslcat.conf")"
        echo "  2. $(msg reminder_2)"
        echo "  3. $(msg reminder_3)"
        echo "  4. $(msg reminder_4)"
        echo "  5. $(msg reminder_5)"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  - $(msg binary): /usr/local/bin/sslcat"
        echo "  - $(msg config): /usr/local/etc/sslcat/sslcat.conf"
        echo "  - $(msg git_hook): /usr/local/bin/sslcat-git-hook"
        echo "  - $(msg git_hook_config): /usr/local/etc/sslcat/git-hook.conf"
        echo "  - $(msg log_dir): /usr/local/var/sslcat/logs"
        echo "  - $(msg git_user): /usr/local/var/git"
        echo "  - $(msg web_dir): /usr/local/var/www"
        echo
        echo "🔧 $(msg management)"
        echo "  - $(msg start): sslcat --config /usr/local/etc/sslcat/sslcat.conf"
        echo "  - $(msg macos_stop)"
        echo "  - $(msg macos_background)"
        echo
        echo "🌐 $(msg web_panel)"
        echo "  - $(msg access_url): http://localhost:8080/sslcat-panel"
        echo "  - $(msg default_user): admin"
        echo "  - $(msg default_pass): admin*9527"
        echo
        echo "⚠️  $(msg important)"
        echo "  1. $(msg reminder_1 "/usr/local/etc/sslcat/sslcat.conf")"
        echo "  2. $(msg reminder_2)"
        echo "  3. $(msg macos_reminder_3)"
        echo "  4. $(msg reminder_4)"
        echo "  5. $(msg reminder_5)"
    fi
    echo
}

# =============================================================================
# 主函数
# =============================================================================

main() {
    # 1. 语言选择（在 check_root 之前，因为非 root 时也要能显示语言选择）
    select_language
    init_messages "$INSTALL_LANG"
    
    # 2. 检查 root（必须在安装步骤前）
    check_root
    check_system
    check_existing_installation
    create_directories
    create_git_user
    install_binary
    install_config
    install_git_hook
    install_systemd_service
    set_permissions
    start_service
    show_installation_info
    
    log_success "$(msg install_complete)"
}

main "$@"
