#!/bin/bash
# ARM64 Mac 上交叉编译 AMD64 Linux 二进制文件

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 在 ARM64 容器内交叉编译 AMD64 版本的 sslcat...${NC}"

# 检查 Docker
if ! docker info >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Docker 未运行，请先启动 Docker Desktop${NC}"
    exit 1
fi

# 创建输出目录
mkdir -p build

echo -e "${BLUE}📦 构建 Docker 镜像（交叉编译）...${NC}"
export DOCKER_BUILDKIT=0
docker build \
    -f Dockerfile.cgo.cross \
    -t sslcat-cgo-cross:latest \
    .

echo -e "${BLUE}📤 提取二进制文件...${NC}"
CONTAINER_ID=$(docker create sslcat-cgo-cross:latest)
docker cp $CONTAINER_ID:/build/sslcat-linux-amd64-cgo ./build/sslcat-linux-amd64-cgo
docker rm $CONTAINER_ID

chmod +x ./build/sslcat-linux-amd64-cgo

echo -e "${GREEN}✅ 交叉编译完成！${NC}"
echo ""
echo -e "${BLUE}📋 文件信息：${NC}"
ls -lh ./build/sslcat-linux-amd64-cgo
file ./build/sslcat-linux-amd64-cgo 2>/dev/null || echo "(file 命令不可用)"
echo ""
echo -e "${BLUE}📍 文件位置：${NC}"
echo "  $(pwd)/build/sslcat-linux-amd64-cgo"
echo ""
echo -e "${GREEN}🎉 现在可以将这个静态链接的 AMD64 二进制文件部署到任何 Linux 服务器了！${NC}"

