#!/bin/bash

# 本地构建并部署到服务器
# 使用方法: ./scripts/build-and-deploy.sh

set -e

# 配置参数
SERVER="whatq.wxside.com"
SERVER_USER="root"
BINARY_NAME="sslcat"
VERSION="1.2.3"

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

# 构建前端
build_frontend() {
    log_info "构建前端..."
    if [ -f "scripts/build-frontend.sh" ]; then
        ./scripts/build-frontend.sh
    else
        log_error "前端构建脚本不存在"
        exit 1
    fi
    log_success "前端构建完成"
}

# 构建 Go 二进制文件
build_binary() {
    log_info "构建 Go 二进制文件..."
    
    # 设置构建参数
    export GOOS=linux
    export GOARCH=amd64
    export CGO_ENABLED=1
    
    # 构建
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$BINARY_NAME" .
    
    if [ ! -f "$BINARY_NAME" ]; then
        log_error "二进制文件构建失败"
        exit 1
    fi
    
    log_success "二进制文件构建完成: $BINARY_NAME"
}

# 部署到服务器
deploy_to_server() {
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
    scp "$BINARY_NAME" "$SERVER_USER@$SERVER:/opt/sslcat/$BINARY_NAME"
    
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
}

# 显示部署信息
show_deployment_info() {
    log_success "部署完成！"
    echo ""
    echo "部署信息："
    echo "  服务器: $SERVER"
    echo "  版本: $VERSION"
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

# 清理临时文件
cleanup() {
    log_info "清理临时文件..."
    rm -f "$BINARY_NAME"
    log_success "清理完成"
}

# 主函数
main() {
    log_info "开始本地构建并部署 SSLcat 到 $SERVER"
    echo ""
    
    build_frontend
    build_binary
    deploy_to_server
    show_deployment_info
    cleanup
}

# 运行主函数
main "$@"
