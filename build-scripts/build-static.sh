#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}⚡ 使用 Docker 编译静态链接的 sslcat (CGO enabled)${NC}"
echo ""

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker 未安装${NC}"
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

# 先构建前端
echo -e "${BLUE}🏗️  构建前端...${NC}"
./scripts/build-frontend.sh

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 前端构建失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ 前端构建完成${NC}"
echo ""

# 构建 Docker 镜像并编译
echo -e "${BLUE}🏗️  构建静态链接二进制文件...${NC}"
docker build \
    --platform linux/amd64 \
    --build-arg HTTP_PROXY=$http_proxy \
    --build-arg HTTPS_PROXY=$https_proxy \
    -f Dockerfile.static \
    -t sslcat-static-builder \
    .

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 构建失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Docker 镜像构建完成${NC}"
echo ""

# 从 Docker 容器中提取二进制文件
echo -e "${BLUE}📦 提取二进制文件...${NC}"
docker create --name sslcat-static-temp sslcat-static-builder
docker cp sslcat-static-temp:/sslcat ./sslcat-static-linux-amd64
docker rm sslcat-static-temp

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 提取失败${NC}"
    exit 1
fi

# 设置可执行权限
chmod +x ./sslcat-static-linux-amd64

echo ""
echo -e "${GREEN}✅ 构建完成！${NC}"
echo ""
echo -e "${BLUE}📊 二进制文件信息：${NC}"
ls -lh ./sslcat-static-linux-amd64
echo ""
file ./sslcat-static-linux-amd64
echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo -e "  - 二进制文件：${GREEN}./sslcat-static-linux-amd64${NC}"
echo -e "  - 这是一个完全静态链接的二进制文件，可以在任何 Linux 发行版上运行"
echo -e "  - 包含 CGO 支持（WebP、SQLite 等）"
echo ""

