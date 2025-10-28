#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}⚡ 使用 musl-cross 本地编译 sslcat (CGO enabled, 静态链接)${NC}"
echo ""

# 检查 musl-cross 是否安装
if ! command -v x86_64-linux-musl-gcc &> /dev/null; then
    echo -e "${RED}❌ musl-cross 未安装${NC}"
    echo -e "${YELLOW}💡 请运行: brew install musl-cross${NC}"
    exit 1
fi

echo -e "${GREEN}✅ musl-cross 工具链检查通过${NC}"
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

# 设置环境变量
export CGO_ENABLED=1
export GOOS=linux
export GOARCH=amd64
export CC=x86_64-linux-musl-gcc
export CXX=x86_64-linux-musl-g++
export CGO_LDFLAGS="-static"

# 获取版本信息
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')

echo -e "${BLUE}🏗️  编译静态链接二进制文件...${NC}"
echo -e "${YELLOW}   版本: ${VERSION}${NC}"
echo -e "${YELLOW}   时间: ${BUILD_TIME}${NC}"
echo -e "${YELLOW}   CC: ${CC}${NC}"
echo ""

# 编译
go build \
    -tags 'sqlite_omit_load_extension' \
    -ldflags "-linkmode external -extldflags '-static' -s -w -X main.version=${VERSION} -X main.build=${BUILD_TIME}" \
    -o sslcat-static-linux-amd64 \
    main.go

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 编译失败${NC}"
    exit 1
fi

# 设置可执行权限
chmod +x ./sslcat-static-linux-amd64

echo ""
echo -e "${GREEN}✅ 编译完成！${NC}"
echo ""
echo -e "${BLUE}📊 二进制文件信息：${NC}"
ls -lh ./sslcat-static-linux-amd64
echo ""
file ./sslcat-static-linux-amd64
echo ""

# 尝试检查依赖（在 Mac 上可能不完全准确）
echo -e "${BLUE}🔍 检查链接类型：${NC}"
if otool -L ./sslcat-static-linux-amd64 2>/dev/null; then
    echo -e "${YELLOW}⚠️  注意：这是 Mac 工具的输出，可能不准确${NC}"
else
    echo -e "${GREEN}✓ 无法使用 otool 检查（这是正常的，因为这是 Linux 二进制文件）${NC}"
fi

echo ""
echo -e "${YELLOW}💡 提示：${NC}"
echo -e "  - 二进制文件：${GREEN}./sslcat-static-linux-amd64${NC}"
echo -e "  - 这是一个使用 musl libc 静态链接的二进制文件"
echo -e "  - 包含 CGO 支持（WebP、SQLite 等）"
echo -e "  - 可以在任何 Linux 发行版上运行（包括 Alpine、Ubuntu、CentOS 等）"
echo -e "  - 请在 Linux 系统上测试运行"
echo ""

