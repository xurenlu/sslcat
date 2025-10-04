#!/bin/bash

# SSLcat CGO Docker 构建脚本（中国优化版）
# 用于在 Docker 中构建 Linux AMD64 CGO 版本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 Docker 是否运行
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker 未运行，请启动 Docker 服务"
        exit 1
    fi
    print_success "Docker 服务正常"
}

# 清理旧的构建缓存
cleanup_build_cache() {
    print_info "清理 Docker 构建缓存..."
    docker builder prune -f >/dev/null 2>&1 || true
    print_success "构建缓存已清理"
}

# 构建 CGO 版本
build_cgo_docker() {
    local tag_name=${1:-"sslcat-cgo:latest"}
    local build_args=""
    
    print_info "开始构建 CGO Docker 镜像..."
    print_info "镜像标签: $tag_name"
    
    # 设置构建参数以加速构建
    build_args="--build-arg GOPROXY=https://goproxy.cn,direct"
    build_args="$build_args --build-arg GOSUMDB=sum.golang.google.cn"
    build_args="$build_args --progress=plain"
    
    # 构建镜像
    if docker build $build_args -f Dockerfile.cgo -t "$tag_name" .; then
        print_success "CGO Docker 镜像构建完成: $tag_name"
        
        # 显示镜像信息
        print_info "镜像信息:"
        docker images "$tag_name" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
        
        # 测试镜像
        print_info "测试镜像..."
        if docker run --rm "$tag_name" --version >/dev/null 2>&1; then
            print_success "镜像测试通过"
        else
            print_warning "镜像测试失败，但构建完成"
        fi
        
        return 0
    else
        print_error "CGO Docker 镜像构建失败"
        return 1
    fi
}

# 提取二进制文件
extract_binary() {
    local tag_name=${1:-"sslcat-cgo:latest"}
    local output_dir=${2:-"build"}
    
    print_info "从 Docker 镜像提取二进制文件..."
    
    # 创建输出目录
    mkdir -p "$output_dir"
    
    # 创建临时容器
    local container_id
    container_id=$(docker create "$tag_name")
    
    # 复制二进制文件
    if docker cp "$container_id:/opt/sslcat/sslcat" "$output_dir/sslcat-linux-amd64-cgo"; then
        print_success "二进制文件已提取到: $output_dir/sslcat-linux-amd64-cgo"
        
        # 设置执行权限
        chmod +x "$output_dir/sslcat-linux-amd64-cgo"
        
        # 显示文件信息
        ls -lh "$output_dir/sslcat-linux-amd64-cgo"
    else
        print_error "二进制文件提取失败"
        return 1
    fi
    
    # 清理临时容器
    docker rm "$container_id" >/dev/null 2>&1
}

# 显示帮助信息
show_help() {
    echo "SSLcat CGO Docker 构建脚本"
    echo ""
    echo "用法:"
    echo "  $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -t, --tag TAG        设置镜像标签 (默认: sslcat-cgo:latest)"
    echo "  -o, --output DIR     输出目录 (默认: build)"
    echo "  -e, --extract        构建后提取二进制文件"
    echo "  -c, --cleanup        构建前清理缓存"
    echo "  -h, --help           显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                           # 基本构建"
    echo "  $0 -t sslcat:v1.0.0         # 指定标签"
    echo "  $0 -e -o dist               # 构建并提取到 dist 目录"
    echo "  $0 -c -e                    # 清理缓存后构建并提取"
}

# 主函数
main() {
    local tag_name="sslcat-cgo:latest"
    local output_dir="build"
    local extract_binary_flag=false
    local cleanup_flag=false
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tag)
                tag_name="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -e|--extract)
                extract_binary_flag=true
                shift
                ;;
            -c|--cleanup)
                cleanup_flag=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_info "开始 SSLcat CGO Docker 构建流程..."
    print_info "使用中国镜像源优化构建速度"
    
    # 检查 Docker
    check_docker
    
    # 清理缓存（如果需要）
    if [[ "$cleanup_flag" == true ]]; then
        cleanup_build_cache
    fi
    
    # 构建镜像
    if build_cgo_docker "$tag_name"; then
        # 提取二进制文件（如果需要）
        if [[ "$extract_binary_flag" == true ]]; then
            extract_binary "$tag_name" "$output_dir"
        fi
        
        print_success "构建流程完成！"
        echo ""
        print_info "可用命令:"
        echo "  运行容器: docker run -p 80:80 -p 443:443 $tag_name"
        echo "  查看镜像: docker images $tag_name"
        echo "  删除镜像: docker rmi $tag_name"
    else
        print_error "构建失败，请检查错误信息"
        exit 1
    fi
}

# 运行主函数
main "$@"
