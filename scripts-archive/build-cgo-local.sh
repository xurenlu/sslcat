#!/bin/bash
# 本地 CGO 快速构建脚本
# 用于在 macOS 上使用 Docker 构建 Linux CGO 二进制文件

set -e

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 开始在 Docker 中构建 CGO 版本的 sslcat...${NC}"

# 检查 Docker
if ! docker info >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Docker 未运行，请先启动 Docker Desktop${NC}"
    exit 1
fi

# 创建输出目录
mkdir -p build

# 构建镜像并提取二进制文件的一步到位方案
echo -e "${BLUE}📦 构建 Docker 镜像...${NC}"
# 使用传统 docker build（不用 BuildKit）避免镜像源问题
export DOCKER_BUILDKIT=0
docker build \
    -f Dockerfile.cgo.build \
    -t sslcat-cgo-builder:latest \
    .

echo -e "${BLUE}📤 提取二进制文件...${NC}"
# 创建临时容器并复制文件
CONTAINER_ID=$(docker create --platform linux/amd64 sslcat-cgo-builder:latest)
docker cp $CONTAINER_ID:/build/sslcat-linux-amd64-cgo ./build/sslcat-linux-amd64-cgo
docker rm $CONTAINER_ID

# 设置权限
chmod +x ./build/sslcat-linux-amd64-cgo

echo -e "${GREEN}✅ 构建完成！${NC}"
echo ""
echo -e "${BLUE}📋 文件信息：${NC}"
ls -lh ./build/sslcat-linux-amd64-cgo
echo ""
echo -e "${BLUE}📍 文件位置：${NC}"
echo "  $(pwd)/build/sslcat-linux-amd64-cgo"
echo ""
echo -e "${GREEN}🎉 现在可以将这个文件部署到 Linux 服务器了！${NC}"

