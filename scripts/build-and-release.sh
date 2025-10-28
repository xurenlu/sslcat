#!/bin/bash

# SSLCat 本地编译和发布脚本
# 支持在本地编译所有平台的 CGO 版本并发布到 GitHub Release

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置
PROJECT_NAME="sslcat"
DIST_DIR="dist"
BUILD_DIR="build"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}║         SSLCat 本地编译和发布脚本 (CGO Enabled)           ║${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 检查必要的工具
echo -e "${BLUE}🔍 检查必要的工具...${NC}"

# 检查 Go
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go 未安装${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Go: $(go version)${NC}"

# 检查 git
if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ Git 未安装${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Git${NC}"

# 检查 gh (GitHub CLI)
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ GitHub CLI (gh) 未安装${NC}"
    echo -e "${YELLOW}💡 请运行: brew install gh${NC}"
    exit 1
fi
echo -e "${GREEN}✓ GitHub CLI${NC}"

# 检查 musl-cross (用于 Linux 静态编译)
if ! command -v x86_64-linux-musl-gcc &> /dev/null; then
    echo -e "${YELLOW}⚠️  musl-cross 未安装，Linux 版本将使用动态链接${NC}"
    echo -e "${YELLOW}💡 推荐安装: brew install musl-cross${NC}"
    HAS_MUSL=false
else
    echo -e "${GREEN}✓ musl-cross${NC}"
    HAS_MUSL=true
fi

# 检查 Zig (可选，用于更好的交叉编译)
if command -v zig &> /dev/null; then
    echo -e "${GREEN}✓ Zig: $(zig version)${NC}"
    HAS_ZIG=true
else
    echo -e "${YELLOW}⚠️  Zig 未安装，将使用标准交叉编译${NC}"
    HAS_ZIG=false
fi

echo ""

# 获取版本信息
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')

echo -e "${MAGENTA}📦 版本信息${NC}"
echo -e "   版本: ${GREEN}${VERSION}${NC}"
echo -e "   时间: ${CYAN}${BUILD_TIME}${NC}"
echo ""

# 询问是否创建新版本
echo -e -n "${YELLOW}是否创建新的 Git 标签？ [y/N]: ${NC}"
read CREATE_TAG
if [[ "$CREATE_TAG" =~ ^[Yy]$ ]]; then
    echo -e -n "${YELLOW}请输入新版本号 (例如 v1.3.20): ${NC}"
    read NEW_VERSION
    if [ -n "$NEW_VERSION" ]; then
        git tag "$NEW_VERSION"
        VERSION="$NEW_VERSION"
        echo -e "${GREEN}✓ 已创建标签: ${VERSION}${NC}"
    fi
fi

echo ""

# 构建前端
echo -e "${BLUE}🏗️  构建前端...${NC}"
./scripts/build-frontend.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 前端构建失败${NC}"
    exit 1
fi
echo -e "${GREEN}✓ 前端构建完成${NC}"
echo ""

# 清理并创建输出目录
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# LDFLAGS
LDFLAGS="-s -w -X main.version=${VERSION} -X main.build=${BUILD_TIME}"

# 定义要编译的平台
declare -A PLATFORMS=(
    ["linux-amd64"]="linux:amd64"
    ["linux-arm64"]="linux:arm64"
    ["darwin-amd64"]="darwin:amd64"
    ["darwin-arm64"]="darwin:arm64"
    ["windows-amd64"]="windows:amd64"
    ["windows-arm64"]="windows:arm64"
)

echo -e "${BLUE}🔨 开始编译所有平台版本...${NC}"
echo ""

# 编译函数
build_platform() {
    local platform=$1
    local os_arch=$2
    local os=$(echo $os_arch | cut -d: -f1)
    local arch=$(echo $os_arch | cut -d: -f2)
    
    echo -e "${CYAN}📦 编译 ${platform}...${NC}"
    
    local output="${BUILD_DIR}/${PROJECT_NAME}"
    if [ "$os" = "windows" ]; then
        output="${output}.exe"
    fi
    
    local archive_name="${PROJECT_NAME}_${VERSION}_${platform}"
    local archive_file=""
    
    # 设置环境变量
    export GOOS=$os
    export GOARCH=$arch
    export CGO_ENABLED=1
    
    # 根据平台选择编译器
    if [ "$os" = "linux" ]; then
        if [ "$HAS_MUSL" = true ]; then
            # 使用 musl-cross 进行静态链接
            if [ "$arch" = "amd64" ]; then
                export CC=x86_64-linux-musl-gcc
                export CXX=x86_64-linux-musl-g++
            elif [ "$arch" = "arm64" ]; then
                export CC=aarch64-linux-musl-gcc
                export CXX=aarch64-linux-musl-g++
            fi
            export CGO_LDFLAGS="-static"
            echo -e "   ${GREEN}使用 musl-cross 静态链接${NC}"
        elif [ "$HAS_ZIG" = true ]; then
            # 使用 Zig 进行交叉编译
            export CC="zig cc -target ${arch}-linux-musl"
            export CXX="zig c++ -target ${arch}-linux-musl"
            export CGO_LDFLAGS="-static"
            echo -e "   ${GREEN}使用 Zig 交叉编译${NC}"
        else
            echo -e "   ${YELLOW}使用标准交叉编译（动态链接）${NC}"
        fi
    elif [ "$os" = "darwin" ]; then
        # macOS 使用系统编译器
        if [ "$(uname)" = "Darwin" ]; then
            export CC="clang"
            export CXX="clang++"
            echo -e "   ${GREEN}使用系统 Clang${NC}"
        else
            echo -e "   ${YELLOW}⚠️  在非 macOS 系统上编译 macOS 版本可能失败${NC}"
        fi
    elif [ "$os" = "windows" ]; then
        # Windows 交叉编译
        if [ "$HAS_ZIG" = true ]; then
            export CC="zig cc -target ${arch}-windows-gnu"
            export CXX="zig c++ -target ${arch}-windows-gnu"
            echo -e "   ${GREEN}使用 Zig 交叉编译${NC}"
        else
            if [ "$arch" = "amd64" ]; then
                export CC=x86_64-w64-mingw32-gcc
                export CXX=x86_64-w64-mingw32-g++
            elif [ "$arch" = "arm64" ]; then
                echo -e "   ${YELLOW}⚠️  Windows ARM64 需要 Zig 或特殊工具链${NC}"
                return 1
            fi
        fi
    fi
    
    # 编译
    mkdir -p "$BUILD_DIR"
    go build \
        -tags 'sqlite_omit_load_extension' \
        -ldflags "${LDFLAGS}" \
        -o "$output" \
        main.go
    
    if [ $? -ne 0 ]; then
        echo -e "   ${RED}✗ 编译失败${NC}"
        return 1
    fi
    
    # 打包
    if [ "$os" = "windows" ]; then
        archive_file="${DIST_DIR}/${archive_name}.zip"
        (cd "$BUILD_DIR" && zip -q "../${archive_file}" "$(basename $output)")
    else
        archive_file="${DIST_DIR}/${archive_name}.tar.gz"
        tar -czf "$archive_file" -C "$BUILD_DIR" "$(basename $output)"
    fi
    
    # 显示文件信息
    local size=$(ls -lh "$archive_file" | awk '{print $5}')
    echo -e "   ${GREEN}✓ 完成: ${archive_file} (${size})${NC}"
    
    # 清理
    rm -f "$output"
    
    return 0
}

# 编译所有平台
SUCCESS_COUNT=0
FAIL_COUNT=0

for platform in "${!PLATFORMS[@]}"; do
    if build_platform "$platform" "${PLATFORMS[$platform]}"; then
        ((SUCCESS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
    echo ""
done

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ 编译完成: ${SUCCESS_COUNT} 个平台${NC}"
if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "${RED}✗ 失败: ${FAIL_COUNT} 个平台${NC}"
fi
echo ""

# 生成 SHA256 校验和
echo -e "${BLUE}🔐 生成 SHA256 校验和...${NC}"
cd "$DIST_DIR"
if command -v sha256sum &> /dev/null; then
    sha256sum *.tar.gz *.zip 2>/dev/null > sha256sum.txt
elif command -v shasum &> /dev/null; then
    shasum -a 256 *.tar.gz *.zip 2>/dev/null > sha256sum.txt
fi
cd ..
echo -e "${GREEN}✓ 校验和已生成${NC}"
echo ""

# 显示编译结果
echo -e "${MAGENTA}📊 编译结果:${NC}"
ls -lh "$DIST_DIR"
echo ""

# 询问是否发布到 GitHub
echo -e -n "${YELLOW}是否发布到 GitHub Release？ [y/N]: ${NC}"
read PUBLISH
if [[ "$PUBLISH" =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${BLUE}🚀 发布到 GitHub Release...${NC}"
    
    # 检查是否已登录 GitHub CLI
    if ! gh auth status &> /dev/null; then
        echo -e "${RED}❌ 未登录 GitHub CLI${NC}"
        echo -e "${YELLOW}💡 请运行: gh auth login${NC}"
        exit 1
    fi
    
    # 询问 Release 说明
    echo -e "${YELLOW}请输入 Release 说明 (按 Ctrl+D 结束):${NC}"
    RELEASE_NOTES=$(cat)
    
    if [ -z "$RELEASE_NOTES" ]; then
        RELEASE_NOTES="Release ${VERSION}"
    fi
    
    # 推送标签（如果有新标签）
    if [[ "$CREATE_TAG" =~ ^[Yy]$ ]] && [ -n "$NEW_VERSION" ]; then
        echo -e "${BLUE}📤 推送标签到 GitHub...${NC}"
        git push origin "$NEW_VERSION"
    fi
    
    # 创建 Release
    echo -e "${BLUE}📝 创建 GitHub Release...${NC}"
    gh release create "$VERSION" \
        --title "SSLCat ${VERSION}" \
        --notes "$RELEASE_NOTES" \
        "$DIST_DIR"/*
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ 发布成功！${NC}"
        echo -e "${CYAN}🔗 查看 Release: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/${VERSION}${NC}"
    else
        echo -e "${RED}❌ 发布失败${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}💡 跳过发布，编译文件保存在 ${DIST_DIR}/ 目录${NC}"
    echo -e "${YELLOW}💡 如需手动发布，请运行:${NC}"
    echo -e "   ${CYAN}gh release create ${VERSION} --title \"SSLCat ${VERSION}\" ${DIST_DIR}/*${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}║                    🎉 全部完成！                           ║${NC}"
echo -e "${GREEN}║                                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"

