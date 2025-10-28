#!/bin/bash

# SSLCat 快速本地编译脚本（所有平台）
# 仅编译，不发布

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}⚡ SSLCat 快速编译（所有平台，CGO Enabled）${NC}"
echo ""

# 配置
DIST_DIR="dist"
BUILD_DIR="build"

# 检查 musl-cross
if command -v x86_64-linux-musl-gcc &> /dev/null; then
    HAS_MUSL=true
    echo -e "${GREEN}✓ musl-cross 可用，Linux 版本将静态链接${NC}"
else
    HAS_MUSL=false
    echo -e "${YELLOW}⚠️  musl-cross 不可用，Linux 版本将动态链接${NC}"
fi

# 检查 aarch64-linux-musl-gcc
if command -v aarch64-linux-musl-gcc &> /dev/null; then
    HAS_MUSL_ARM64=true
    echo -e "${GREEN}✓ aarch64-linux-musl-gcc 可用${NC}"
else
    HAS_MUSL_ARM64=false
    echo -e "${YELLOW}⚠️  aarch64-linux-musl-gcc 不可用，Linux ARM64 将跳过或动态链接${NC}"
fi

echo ""

# 构建前端
echo -e "${BLUE}🏗️  构建前端...${NC}"
./scripts/build-frontend.sh
echo ""

# 清理
rm -rf "$DIST_DIR" "$BUILD_DIR"
mkdir -p "$DIST_DIR" "$BUILD_DIR"

# 版本信息
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS="-s -w -X main.version=${VERSION} -X main.build=${BUILD_TIME}"

echo -e "${BLUE}📦 版本: ${VERSION}${NC}"
echo ""

# 1. Linux AMD64 (静态链接)
if [ "$HAS_MUSL" = true ]; then
    echo -e "${BLUE}🐧 编译 Linux AMD64 (静态链接)...${NC}"
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64 \
    CC=x86_64-linux-musl-gcc \
    CXX=x86_64-linux-musl-g++ \
    CGO_LDFLAGS="-static" \
    go build -tags 'sqlite_omit_load_extension' -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/sslcat" main.go
    
    tar -czf "${DIST_DIR}/sslcat_${VERSION}_linux_amd64.tar.gz" -C "${BUILD_DIR}" sslcat
    rm "${BUILD_DIR}/sslcat"
    echo -e "${GREEN}✓ Linux AMD64 完成${NC}"
else
    echo -e "${YELLOW}⊘ Linux AMD64 跳过（需要 musl-cross）${NC}"
fi
echo ""

# 2. Linux ARM64 (静态链接)
if [ "$HAS_MUSL_ARM64" = true ]; then
    echo -e "${BLUE}🐧 编译 Linux ARM64 (静态链接)...${NC}"
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=arm64 \
    CC=aarch64-linux-musl-gcc \
    CXX=aarch64-linux-musl-g++ \
    CGO_LDFLAGS="-static" \
    go build -tags 'sqlite_omit_load_extension' -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/sslcat" main.go
    
    tar -czf "${DIST_DIR}/sslcat_${VERSION}_linux_arm64.tar.gz" -C "${BUILD_DIR}" sslcat
    rm "${BUILD_DIR}/sslcat"
    echo -e "${GREEN}✓ Linux ARM64 完成${NC}"
else
    echo -e "${YELLOW}⊘ Linux ARM64 跳过（需要 aarch64-linux-musl-gcc）${NC}"
fi
echo ""

# 3. macOS AMD64
if [ "$(uname)" = "Darwin" ]; then
    echo -e "${BLUE}🍎 编译 macOS AMD64...${NC}"
    CGO_ENABLED=1 \
    GOOS=darwin \
    GOARCH=amd64 \
    go build -tags 'sqlite_omit_load_extension' -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/sslcat" main.go
    
    tar -czf "${DIST_DIR}/sslcat_${VERSION}_darwin_amd64.tar.gz" -C "${BUILD_DIR}" sslcat
    rm "${BUILD_DIR}/sslcat"
    echo -e "${GREEN}✓ macOS AMD64 完成${NC}"
else
    echo -e "${YELLOW}⊘ macOS AMD64 跳过（需要在 macOS 上编译）${NC}"
fi
echo ""

# 4. macOS ARM64 (M1/M2)
if [ "$(uname)" = "Darwin" ]; then
    echo -e "${BLUE}🍎 编译 macOS ARM64 (M1/M2)...${NC}"
    CGO_ENABLED=1 \
    GOOS=darwin \
    GOARCH=arm64 \
    go build -tags 'sqlite_omit_load_extension' -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/sslcat" main.go
    
    tar -czf "${DIST_DIR}/sslcat_${VERSION}_darwin_arm64.tar.gz" -C "${BUILD_DIR}" sslcat
    rm "${BUILD_DIR}/sslcat"
    echo -e "${GREEN}✓ macOS ARM64 完成${NC}"
else
    echo -e "${YELLOW}⊘ macOS ARM64 跳过（需要在 macOS 上编译）${NC}"
fi
echo ""

# 5. Windows AMD64 (如果有 Zig)
if command -v zig &> /dev/null; then
    echo -e "${BLUE}🪟 编译 Windows AMD64...${NC}"
    CGO_ENABLED=1 \
    GOOS=windows \
    GOARCH=amd64 \
    CC="zig cc -target x86_64-windows-gnu" \
    CXX="zig c++ -target x86_64-windows-gnu" \
    go build -tags 'sqlite_omit_load_extension' -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/sslcat.exe" main.go
    
    (cd "${BUILD_DIR}" && zip -q "../${DIST_DIR}/sslcat_${VERSION}_windows_amd64.zip" sslcat.exe)
    rm "${BUILD_DIR}/sslcat.exe"
    echo -e "${GREEN}✓ Windows AMD64 完成${NC}"
else
    echo -e "${YELLOW}⊘ Windows AMD64 跳过（需要 Zig: brew install zig）${NC}"
fi
echo ""

# 6. Windows ARM64 (如果有 Zig)
if command -v zig &> /dev/null; then
    echo -e "${BLUE}🪟 编译 Windows ARM64...${NC}"
    CGO_ENABLED=1 \
    GOOS=windows \
    GOARCH=arm64 \
    CC="zig cc -target aarch64-windows-gnu" \
    CXX="zig c++ -target aarch64-windows-gnu" \
    go build -tags 'sqlite_omit_load_extension' -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/sslcat.exe" main.go
    
    (cd "${BUILD_DIR}" && zip -q "../${DIST_DIR}/sslcat_${VERSION}_windows_arm64.zip" sslcat.exe)
    rm "${BUILD_DIR}/sslcat.exe"
    echo -e "${GREEN}✓ Windows ARM64 完成${NC}"
else
    echo -e "${YELLOW}⊘ Windows ARM64 跳过（需要 Zig: brew install zig）${NC}"
fi
echo ""

# 生成校验和
echo -e "${BLUE}🔐 生成 SHA256 校验和...${NC}"
cd "$DIST_DIR"
if command -v sha256sum &> /dev/null; then
    sha256sum * 2>/dev/null > sha256sum.txt
elif command -v shasum &> /dev/null; then
    shasum -a 256 * 2>/dev/null > sha256sum.txt
fi
cd ..
echo ""

# 显示结果
echo -e "${GREEN}✅ 编译完成！${NC}"
echo ""
echo -e "${BLUE}📊 编译结果:${NC}"
ls -lh "$DIST_DIR"
echo ""
echo -e "${YELLOW}💡 提示:${NC}"
echo -e "   - 文件保存在 ${BLUE}${DIST_DIR}/${NC} 目录"
echo -e "   - 使用 ${BLUE}./scripts/build-and-release.sh${NC} 可以直接发布到 GitHub"
echo ""

