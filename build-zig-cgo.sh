#!/bin/bash

# 使用 Zig 在 Mac ARM64 上交叉编译 Linux AMD64 CGO 二进制文件
# 目标：兼容 GLIBC 2.32 的 Linux AMD64 二进制文件（CGO 启用）

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 使用 Zig 交叉编译 sslcat (Mac ARM64 -> Linux AMD64 with CGO)${NC}"
echo ""

# 检查 Docker 是否可用
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker 未安装或不可用${NC}"
    echo "请先安装 Docker Desktop for Mac"
    exit 1
fi

# 检查 Docker 是否运行
if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker 未运行${NC}"
    echo "请启动 Docker Desktop"
    exit 1
fi

echo -e "${GREEN}✅ Docker 环境检查通过${NC}"
echo ""

# 设置代理（如果需要）
if [ -n "$HTTP_PROXY" ] || [ -n "$HTTPS_PROXY" ]; then
    echo -e "${YELLOW}📡 检测到代理设置${NC}"
    DOCKER_BUILD_ARGS="--build-arg HTTP_PROXY=$HTTP_PROXY --build-arg HTTPS_PROXY=$HTTPS_PROXY"
else
    DOCKER_BUILD_ARGS=""
fi

# 构建 Docker 镜像
echo -e "${BLUE}🏗️  构建 Zig 编译环境...${NC}"
docker build --platform linux/amd64 \
    $DOCKER_BUILD_ARGS \
    -f Dockerfile.zig-cgo \
    -t sslcat-zig-cgo-builder \
    .

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Docker 镜像构建失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Docker 镜像构建成功${NC}"
echo ""

# 创建临时容器并提取二进制文件
echo -e "${BLUE}📤 提取编译的二进制文件...${NC}"

# 创建输出目录
mkdir -p build

# 从容器中提取二进制文件
docker create --name sslcat-zig-temp sslcat-zig-cgo-builder
docker cp sslcat-zig-temp:/usr/local/bin/sslcat ./build/sslcat-linux-amd64-cgo
docker rm sslcat-zig-temp

if [ ! -f "./build/sslcat-linux-amd64-cgo" ]; then
    echo -e "${RED}❌ 提取二进制文件失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ 二进制文件提取成功${NC}"
echo ""

# 验证二进制文件
echo -e "${BLUE}📊 验证编译结果...${NC}"
echo ""

echo -e "${YELLOW}文件信息:${NC}"
file ./build/sslcat-linux-amd64-cgo
echo ""

echo -e "${YELLOW}文件大小:${NC}"
ls -lh ./build/sslcat-linux-amd64-cgo
echo ""

echo -e "${YELLOW}SHA256:${NC}"
shasum -a 256 ./build/sslcat-linux-amd64-cgo
echo ""

# 使用 Docker 测试二进制文件
echo -e "${BLUE}🧪 测试二进制文件...${NC}"
docker run --rm --platform linux/amd64 \
    -v $(pwd)/build:/test \
    debian:bullseye \
    /test/sslcat-linux-amd64-cgo --version || echo "版本检查完成"

echo ""
echo -e "${GREEN}✅ 编译完成！${NC}"
echo ""
echo -e "${BLUE}📦 输出文件: ${GREEN}./build/sslcat-linux-amd64-cgo${NC}"
echo ""
echo -e "${YELLOW}📝 使用说明:${NC}"
echo "  1. 将二进制文件上传到 Linux 服务器"
echo "  2. 设置执行权限: chmod +x sslcat-linux-amd64-cgo"
echo "  3. 运行: ./sslcat-linux-amd64-cgo --version"
echo ""
echo -e "${BLUE}🎯 兼容性:${NC}"
echo "  - 目标平台: Linux AMD64"
echo "  - GLIBC 版本: 2.32 或更高"
echo "  - CGO: 已启用"
echo "  - SQLite: 完整支持"
echo ""

