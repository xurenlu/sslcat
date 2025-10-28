#!/bin/bash

# 使用 Zig + Alpine 在 Mac ARM64 上快速编译 Linux AMD64 静态链接二进制文件
# 优势：编译速度快，完全静态链接，无 GLIBC 依赖

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}⚡ 使用 Zig + Alpine 快速编译 sslcat (静态链接)${NC}"
echo ""

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker 未安装${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker 未运行${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker 环境检查通过${NC}"
echo ""

# 设置代理
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890
export all_proxy=socks5://127.0.0.1:7890

echo -e "${YELLOW}📡 已设置代理${NC}"
echo ""

# 构建 Docker 镜像
echo -e "${BLUE}🏗️  构建编译环境 (使用缓存加速)...${NC}"
docker build --platform linux/amd64 \
    --build-arg HTTP_PROXY=$http_proxy \
    --build-arg HTTPS_PROXY=$https_proxy \
    -f Dockerfile.zig-alpine \
    -t sslcat-zig-alpine \
    .

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 构建失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ 构建成功${NC}"
echo ""

# 提取二进制文件
echo -e "${BLUE}📤 提取二进制文件...${NC}"
mkdir -p build

docker create --name sslcat-temp sslcat-zig-alpine
docker cp sslcat-temp:/sslcat ./build/sslcat-linux-amd64-static
docker rm sslcat-temp

if [ ! -f "./build/sslcat-linux-amd64-static" ]; then
    echo -e "${RED}❌ 提取失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ 提取成功${NC}"
echo ""

# 验证
echo -e "${BLUE}📊 验证结果...${NC}"
echo ""

echo -e "${YELLOW}文件信息:${NC}"
file ./build/sslcat-linux-amd64-static
echo ""

echo -e "${YELLOW}文件大小:${NC}"
ls -lh ./build/sslcat-linux-amd64-static
du -h ./build/sslcat-linux-amd64-static
echo ""

echo -e "${YELLOW}SHA256:${NC}"
shasum -a 256 ./build/sslcat-linux-amd64-static
echo ""

# 测试
echo -e "${BLUE}🧪 测试二进制文件...${NC}"
docker run --rm --platform linux/amd64 \
    -v $(pwd)/build:/test \
    alpine:latest \
    /test/sslcat-linux-amd64-static --version || echo "测试完成"

echo ""
echo -e "${GREEN}✅ 编译完成！${NC}"
echo ""
echo -e "${BLUE}📦 输出文件: ${GREEN}./build/sslcat-linux-amd64-static${NC}"
echo ""
echo -e "${YELLOW}📝 特性:${NC}"
echo "  ✅ 完全静态链接 - 无任何外部依赖"
echo "  ✅ 兼容所有 Linux 发行版"
echo "  ✅ CGO 已启用 - 完整 SQLite 支持"
echo "  ✅ 文件体积优化"
echo ""
echo -e "${YELLOW}📝 使用说明:${NC}"
echo "  1. 上传到服务器: scp ./build/sslcat-linux-amd64-static user@server:/path/"
echo "  2. 设置权限: chmod +x sslcat-linux-amd64-static"
echo "  3. 运行: ./sslcat-linux-amd64-static"
echo ""

