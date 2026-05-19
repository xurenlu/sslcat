#!/bin/bash
set -euo pipefail

# =============================================================================
# SSLcat 自动升级脚本 / SSLcat Auto Upgrade Script
# 自动检测最新版本并下载安装 / Auto detect latest version and install
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR=$(mktemp -d)
trap "rm -rf '$TEMP_DIR'" EXIT

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 语言检测
detect_locale() {
    local lang_var="${LANG:-}${LC_ALL:-}${LC_MESSAGES:-}"
    if [[ -z "$lang_var" ]]; then
        echo "en"
        return
    fi
    if [[ "$lang_var" =~ ^[zZ][hH] ]]; then
        echo "zh"
    else
        echo "en"
    fi
}

LANG=$(detect_locale)

# 多语言消息
if [[ "$LANG" == "zh" ]]; then
    MSG_CHECKING="正在检查最新版本..."
    MSG_CURRENT="当前版本: %s"
    MSG_LATEST="最新版本: %s"
    MSG_UP_TO_DATE="已经是最新版本，无需升级"
    MSG_DOWNLOADING="正在下载 SSLcat %s..."
    MSG_EXTRACTING="正在解压..."
    MSG_INSTALLING="正在安装..."
    MSG_SUCCESS="升级成功！"
    MSG_FAILED="下载失败: %s"
    MSG_NO_RELEASE="未找到适用于当前系统的 Release"
    MSG_UNSUPPORTED="不支持的操作系统"
    MSG_SKIP_INSTALL="跳过安装步骤，仅下载"
else
    MSG_CHECKING="Checking for latest version..."
    MSG_CURRENT="Current version: %s"
    MSG_LATEST="Latest version: %s"
    MSG_UP_TO_DATE="Already up to date"
    MSG_DOWNLOADING="Downloading SSLcat %s..."
    MSG_EXTRACTING="Extracting..."
    MSG_INSTALLING="Installing..."
    MSG_SUCCESS="Upgrade completed!"
    MSG_FAILED="Download failed: %s"
    MSG_NO_RELEASE="No suitable release found for your system"
    MSG_UNSUPPORTED="Unsupported operating system"
    MSG_SKIP_INSTALL="Skipping installation, download only"
fi

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 检测操作系统和架构
detect_system() {
    local OS
    local ARCH

    case "$(uname -s)" in
        Linux)
            OS="linux"
            ;;
        Darwin)
            OS="darwin"
            ;;
        *)
            echo "unsupported"
            return
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            echo "unsupported"
            return
            ;;
    esac

    echo "${OS}-${ARCH}"
}

# 获取最新版本号
get_latest_version() {
    # 使用 GitHub API 获取最新 release
    local latest_url
    local api_output

    api_output=$(curl -s https://api.github.com/repos/xurenlu/sslcat/releases/latest) || {
        return 1
    }

    if [[ -z "$api_output" ]]; then
        return 1
    fi

    # 尝试使用 jq 解析，如果不可用则用 grep+sed
    if command -v jq &> /dev/null; then
        latest_url=$(echo "$api_output" | jq -r '.tag_name // empty')
    else
        latest_url=$(echo "$api_output" | grep '"tag_name"' | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi

    if [[ -z "$latest_url" ]]; then
        return 1
    fi

    # 移除 'v' 前缀
    echo "${latest_url#v}"
}

# 获取当前版本号
get_current_version() {
    if command -v sslcat &> /dev/null; then
        sslcat version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown"
    else
        echo "not_installed"
    fi
}

# 下载 Release
download_release() {
    local version="$1"
    local system="$2"
    local output_dir="$3"

    local filename="sslcat-${version}-${system}.tar.gz"
    local download_url="https://github.com/xurenlu/sslcat/releases/download/v${version}/${filename}"

    log_info "$(printf "$MSG_DOWNLOADING" "$version")"
    log_info "下载地址: $download_url"

    if curl -L -o "${output_dir}/${filename}" "$download_url" --progress-bar; then
        echo "${output_dir}/${filename}"
    else
        log_error "$(printf "$MSG_FAILED" "$download_url")"
        return 1
    fi
}

# 解压并安装
extract_and_install() {
    local archive="$1"
    local extract_dir="$2"

    log_info "$MSG_EXTRACTING"

    # 解压到临时目录
    if ! tar -xzf "$archive" -C "$extract_dir"; then
        log_error "解压失败"
        return 1
    fi

    log_success "$MSG_EXTRACTING"

    # 进入解压后的目录
    cd "$extract_dir" || return 1

    # 列出解压后的内容（调试用）
    log_info "解压内容:"
    ls -la

    # 检查是否存在 install-sslcat.sh
    if [[ -f "install-sslcat.sh" ]]; then
        # 直接在当前目录
        :
    elif [[ -f "sslcat/install-sslcat.sh" ]]; then
        # 在子目录中
        cd sslcat || return 1
    elif [[ -f "sslcat-*/install-sslcat.sh" ]]; then
        # 使用通配符找到子目录
        cd sslcat-* || return 1
    else
        log_error "install-sslcat.sh 未找到"
        log_error "查找失败，当前目录内容:"
        ls -laR
        return 1
    fi

    # 添加执行权限
    chmod +x install-sslcat.sh

    log_info "$MSG_INSTALLING"

    # 执行安装脚本（静默模式）
    if ./install-sslcat.sh -s; then
        log_success "$MSG_SUCCESS"
        return 0
    else
        log_error "安装失败"
        return 1
    fi
}

# 主函数
main() {
    echo "=========================================="
    echo "  SSLcat Auto Upgrade Script"
    echo "=========================================="
    echo ""

    # 检测系统
    local system
    system=$(detect_system)

    if [[ "$system" == "unsupported" ]]; then
        log_error "$MSG_UNSUPPORTED"
        exit 1
    fi

    log_info "检测到系统: $system"

    # 获取版本信息
    local current_version
    local latest_version

    current_version=$(get_current_version)

    log_info "$MSG_CHECKING"
    latest_version=$(get_latest_version)

    if [[ -z "$latest_version" ]]; then
        log_error "无法获取最新版本信息"
        exit 1
    fi

    log_info "$(printf "$MSG_CURRENT" "$current_version")"
    log_info "$(printf "$MSG_LATEST" "$latest_version")"

    # 检查是否需要升级
    if [[ "$current_version" == "$latest_version" ]]; then
        log_success "$MSG_UP_TO_DATE"
        exit 0
    fi

    echo ""
    log_warn "发现新版本，准备升级..."
    echo ""

    # 下载 Release
    local archive
    archive=$(download_release "$latest_version" "$system" "$TEMP_DIR")

    if [[ -z "$archive" ]] || [[ ! -f "$archive" ]]; then
        exit 1
    fi

    # 解压并安装
    if ! extract_and_install "$archive" "$TEMP_DIR"; then
        exit 1
    fi

    # 清理
    cd "$SCRIPT_DIR"
}

# 解析命令行参数
SKIP_INSTALL=false
VERSION_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--download-only)
            SKIP_INSTALL=true
            shift
            ;;
        -v|--version-only)
            VERSION_ONLY=true
            shift
            ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  -d, --download-only    仅下载，不安装"
            echo "  -v, --version-only     仅检查版本"
            echo "  -h, --help             显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  $0              # 检查并升级到最新版本"
            echo "  $0 -d           # 仅下载最新版本"
            echo "  $0 -v           # 仅检查版本信息"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            echo "使用 -h 查看帮助"
            exit 1
            ;;
    esac
done

# 如果只是检查版本
if [[ "$VERSION_ONLY" == true ]]; then
    current_version=$(get_current_version)

    log_info "$MSG_CHECKING"
    latest_version=$(get_latest_version)

    if [[ -z "$latest_version" ]]; then
        log_error "无法获取最新版本信息"
        exit 1
    fi

    log_info "$(printf "$MSG_CURRENT" "$current_version")"
    log_info "$(printf "$MSG_LATEST" "$latest_version")"

    if [[ "$current_version" == "$latest_version" ]]; then
        log_success "$MSG_UP_TO_DATE"
        exit 0
    else
        log_warn "发现新版本: $latest_version"
        exit 1
    fi
fi

# 执行主程序
main
