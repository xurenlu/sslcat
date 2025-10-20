#!/bin/bash
# 构建 ARM64 Linux CGO 二进制文件

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 构建 ARM64 版本的 sslcat（启用 CGO）...${NC}"
echo -e "${YELLOW}注意：这是 ARM64 版本，适用于 ARM64 Linux 服务器${NC}"

# 检查 Docker
if ! docker info >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Docker 未运行，请先启动 Docker Desktop${NC}"
    exit 1
fi

# 创建输出目录
mkdir -p build

echo -e "${BLUE}📦 构建 Docker 镜像...${NC}"
export DOCKER_BUILDKIT=0
docker build \
    -f Dockerfile.cgo.arm64 \
    -t sslcat-cgo-arm64:latest \
    .

echo -e "${BLUE}📤 提取二进制文件...${NC}"
CONTAINER_ID=$(docker create sslcat-cgo-arm64:latest)
docker cp $CONTAINER_ID:/build/sslcat-linux-arm64-cgo ./build/sslcat-linux-arm64-cgo
docker rm $CONTAINER_ID

chmod +x ./build/sslcat-linux-arm64-cgo

echo -e "${GREEN}✅ 构建完成！${NC}"
echo ""
echo -e "${BLUE}📋 文件信息：${NC}"
ls -lh ./build/sslcat-linux-arm64-cgo
echo ""
echo -e "${BLUE}📍 文件位置：${NC}"
echo "  $(pwd)/build/sslcat-linux-arm64-cgo"
echo ""
echo -e "${GREEN}🎉 这是 ARM64 版本，可以部署到 ARM64 Linux 服务器！${NC}"
echo -e "${BLUE}💡 如需 AMD64 版本，请在 AMD64 机器上运行此脚本${NC}"

