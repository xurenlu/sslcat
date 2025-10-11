#!/bin/bash
# 使用 Zig 交叉编译 AMD64 Linux 二进制文件

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 使用 Zig 交叉编译 AMD64 版本的 sslcat...${NC}"
echo -e "${YELLOW}💡 Zig 是一个支持零配置交叉编译的 C 编译器${NC}"

# 检查 Docker
if ! docker info >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Docker 未运行，请先启动 Docker Desktop${NC}"
    exit 1
fi

# 创建输出目录
mkdir -p build

echo -e "${BLUE}📦 构建 Docker 镜像（这可能需要几分钟，首次需要下载 Zig）...${NC}"
export DOCKER_BUILDKIT=0
docker build \
    -f Dockerfile.cgo.zig \
    -t sslcat-cgo-zig:latest \
    .

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️  构建失败，可能是网络问题导致无法下载 Zig${NC}"
    exit 1
fi

echo -e "${BLUE}📤 提取二进制文件...${NC}"
CONTAINER_ID=$(docker create sslcat-cgo-zig:latest)
docker cp $CONTAINER_ID:/build/sslcat-linux-amd64-cgo ./build/sslcat-linux-amd64-cgo
docker rm $CONTAINER_ID

chmod +x ./build/sslcat-linux-amd64-cgo

echo -e "${GREEN}✅ 交叉编译完成！${NC}"
echo ""
echo -e "${BLUE}📋 文件信息：${NC}"
ls -lh ./build/sslcat-linux-amd64-cgo
echo ""
echo -e "${BLUE}📍 文件位置：${NC}"
echo "  $(pwd)/build/sslcat-linux-amd64-cgo"
echo ""
echo -e "${GREEN}🎉 AMD64 二进制文件已就绪，可以部署到 x86_64 Linux 服务器了！${NC}"

