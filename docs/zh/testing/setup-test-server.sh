#!/bin/bash

# SSLcat 模板测试服务器环境设置脚本
# 用于在 sg2.shifen.de 上设置测试环境

set -e

SERVER="root@sg2.shifen.de"
WORK_DIR="/opt/sslcat-test"
SSLCAT_DIR="/opt/sslcat"

echo "🚀 开始设置测试服务器环境..."

# 检查 SSH 连接
echo "📡 检查 SSH 连接..."
ssh -o ConnectTimeout=10 $SERVER "echo 'SSH 连接成功'" || {
    echo "❌ 无法连接到服务器，请检查 SSH 配置"
    exit 1
}

# 在服务器上执行设置命令
ssh $SERVER bash << 'ENDSSH'
set -e

echo "📦 检查系统信息..."
uname -a
df -h
free -h

echo "🔧 安装必要工具..."

# 检查并安装 Docker
if ! command -v docker &> /dev/null; then
    echo "安装 Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "✅ Docker 已安装: $(docker --version)"
fi

# 检查并安装 Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "安装 Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
else
    echo "✅ Docker Compose 已安装"
fi

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

# 工具链留在应用专用目录，不覆盖全局 Go 或修改 /etc/profile。
install_go() {
    local go_install_dir="/opt/sslcat-toolchains/go${GO_REQUIRED_VERSION}"
    if ! select_go_toolchain; then
        install_go_toolchain "$go_install_dir" || return 1
        select_go_toolchain || return 1
    fi
    printf 'Go已就绪: %s\n' "$GOROOT"
}

install_go

# 检查并安装 Git
if ! command -v git &> /dev/null; then
    echo "安装 Git..."
    if command -v yum &> /dev/null; then
        yum install -y git
    elif command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y git
    fi
else
    echo "✅ Git 已安装: $(git --version)"
fi

# 检查并安装 jq
if ! command -v jq &> /dev/null; then
    echo "安装 jq..."
    if command -v yum &> /dev/null; then
        yum install -y jq
    elif command -v apt-get &> /dev/null; then
        apt-get install -y jq
    fi
else
    echo "✅ jq 已安装"
fi

# 创建测试目录
mkdir -p $WORK_DIR
mkdir -p $SSLCAT_DIR

echo "✅ 环境设置完成"
ENDSSH

echo "✅ 服务器环境设置完成！"
echo ""
echo "下一步："
echo "1. 克隆或同步 sslcat 代码到服务器"
echo "2. 编译 SSLcat"
echo "3. 运行测试脚本"

