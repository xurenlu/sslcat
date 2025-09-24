#!/bin/bash

# 部署脚本：从 GitHub Release 下载并部署到服务器
# 使用方法: ./scripts/deploy-to-server.sh [版本号] [服务器地址]

set -e

# 配置参数
REPO="xurenlu/withssl"  # 替换为您的 GitHub 仓库
SERVER="whatq.wxside.com"
SERVER_USER="root"
VERSION=${1:-"latest"}
BINARY_NAME="sslcat"
ARCH="linux-amd64"

# 颜色输出
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

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    if ! command -v curl &> /dev/null; then
        log_error "curl 未安装，请先安装 curl"
        exit 1
    fi
    
    if ! command -v ssh &> /dev/null; then
        log_error "ssh 未安装，请先安装 ssh"
        exit 1
    fi
    
    log_success "依赖检查完成"
}

# 获取最新版本信息
get_latest_version() {
    if [ "$VERSION" = "latest" ]; then
        log_info "获取最新版本..."
        VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
        if [ -z "$VERSION" ]; then
            log_error "无法获取最新版本"
            exit 1
        fi
        log_info "最新版本: $VERSION"
    fi
}

# 下载二进制文件
download_binary() {
    log_info "下载二进制文件..."
    
    # 构建下载 URL
    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/${BINARY_NAME}_${VERSION}_${ARCH}.tar.gz"
    else
        DOWNLOAD_URL="https://github.com/$REPO/releases/download/v${VERSION}/${BINARY_NAME}_v${VERSION}_${ARCH}.tar.gz"
    fi
    
    log_info "下载地址: $DOWNLOAD_URL"
    
    # 创建临时目录
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # 下载文件
    if ! curl -L -o "${BINARY_NAME}.tar.gz" "$DOWNLOAD_URL"; then
        log_error "下载失败，请检查版本号和网络连接"
        exit 1
    fi
    
    # 解压文件
    tar -xzf "${BINARY_NAME}.tar.gz"
    
    if [ ! -f "$BINARY_NAME" ]; then
        log_error "解压后未找到二进制文件"
        exit 1
    fi
    
    log_success "二进制文件下载完成"
    echo "$TEMP_DIR/$BINARY_NAME"
}

# 部署到服务器
deploy_to_server() {
    local binary_path="$1"
    
    log_info "部署到服务器 $SERVER..."
    
    # 检查服务器连接
    if ! ssh -o ConnectTimeout=10 "$SERVER_USER@$SERVER" "echo '连接成功'"; then
        log_error "无法连接到服务器 $SERVER"
        exit 1
    fi
    
    # 在服务器上创建备份
    log_info "创建备份..."
    ssh "$SERVER_USER@$SERVER" "
        if [ -f /opt/sslcat/$BINARY_NAME ]; then
            mkdir -p /opt/sslcat-backups/\$(date +%Y%m%d_%H%M%S)
            cp /opt/sslcat/$BINARY_NAME /opt/sslcat-backups/\$(date +%Y%m%d_%H%M%S)/
            echo '备份完成'
        fi
    "
    
    # 停止服务
    log_info "停止服务..."
    ssh "$SERVER_USER@$SERVER" "
        if systemctl is-active --quiet sslcat; then
            systemctl stop sslcat
            echo '服务已停止'
        fi
    " || log_warning "服务可能未运行"
    
    # 上传新二进制文件
    log_info "上传新二进制文件..."
    scp "$binary_path" "$SERVER_USER@$SERVER:/opt/sslcat/$BINARY_NAME"
    
    # 设置权限
    log_info "设置权限..."
    ssh "$SERVER_USER@$SERVER" "
        chmod +x /opt/sslcat/$BINARY_NAME
        chown sslcat:sslcat /opt/sslcat/$BINARY_NAME
    "
    
    # 启动服务
    log_info "启动服务..."
    ssh "$SERVER_USER@$SERVER" "
        systemctl daemon-reload
        systemctl start sslcat
        systemctl enable sslcat
    "
    
    # 检查服务状态
    log_info "检查服务状态..."
    if ssh "$SERVER_USER@$SERVER" "systemctl is-active --quiet sslcat"; then
        log_success "服务启动成功"
    else
        log_error "服务启动失败"
        ssh "$SERVER_USER@$SERVER" "systemctl status sslcat"
        exit 1
    fi
    
    # 清理临时文件
    rm -rf "$(dirname "$binary_path")"
}

# 显示部署信息
show_deployment_info() {
    log_success "部署完成！"
    echo ""
    echo "部署信息："
    echo "  服务器: $SERVER"
    echo "  版本: $VERSION"
    echo "  架构: $ARCH"
    echo "  二进制: /opt/sslcat/$BINARY_NAME"
    echo ""
    echo "管理命令："
    echo "  查看状态: ssh $SERVER_USER@$SERVER 'systemctl status sslcat'"
    echo "  查看日志: ssh $SERVER_USER@$SERVER 'journalctl -u sslcat -f'"
    echo "  重启服务: ssh $SERVER_USER@$SERVER 'systemctl restart sslcat'"
    echo ""
    echo "访问地址："
    echo "  管理界面: https://$SERVER/sslcat-panel"
    echo "  API 接口: https://$SERVER/api"
}

# 主函数
main() {
    log_info "开始部署 SSLcat 到 $SERVER"
    echo ""
    
    check_dependencies
    get_latest_version
    
    local binary_path
    binary_path=$(download_binary)
    
    deploy_to_server "$binary_path"
    show_deployment_info
}

# 运行主函数
main "$@"
