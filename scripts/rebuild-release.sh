#!/usr/bin/env bash

# 重新构建和打包 release 的脚本

set -e

VERSION="v1.3.22"
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
PROJECT_NAME="sslcat"
DIST_DIR="dist"
BUILD_DIR="build"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.build=${BUILD_TIME}"

echo "🚀 开始重新构建和打包 ${VERSION}..."

# 清理
rm -rf "$DIST_DIR" "$BUILD_DIR"
mkdir -p "$DIST_DIR" "$BUILD_DIR"

# 构建函数
build_and_package() {
    local platform=$1
    local os=$2
    local arch=$3
    
    echo "📦 构建 ${platform}..."
    
    export GOOS=$os
    export GOARCH=$arch
    export CGO_ENABLED=1
    
    local output="${BUILD_DIR}/${PROJECT_NAME}"
    if [ "$os" = "windows" ]; then
        output="${output}.exe"
    fi
    
    # 编译
    go build \
        -tags 'sqlite_omit_load_extension' \
        -ldflags "${LDFLAGS}" \
        -o "$output" \
        main.go
    
    if [ $? -ne 0 ]; then
        echo "❌ ${platform} 构建失败"
        return 1
    fi
    
    # 创建发布包目录
    local package_dir="${BUILD_DIR}/release-package-${platform}"
    mkdir -p "$package_dir"
    
    # 复制二进制文件
    cp "$output" "$package_dir/${PROJECT_NAME}"
    if [ "$os" = "windows" ]; then
        cp "$output" "$package_dir/${PROJECT_NAME}.exe"
    fi
    
    # 复制配置文件
    cp sslcat.conf "$package_dir/sslcat.conf"
    cp sslcat.service "$package_dir/sslcat.service"
    cp install-sslcat.sh "$package_dir/install-sslcat.sh"
    chmod +x "$package_dir/install-sslcat.sh"
    
    # 复制 Git Hook 脚本
    cp scripts/sslcat-git-hook "$package_dir/sslcat-git-hook"
    chmod +x "$package_dir/sslcat-git-hook"
    cp scripts/install-git-hook.sh "$package_dir/install-git-hook.sh"
    chmod +x "$package_dir/install-git-hook.sh"
    
    # 创建 README
    cat > "$package_dir/README.md" <<EOF
# SSLcat Release Package

## Quick Install

1. Extract files: tar -xzf sslcat_*.tar.gz
2. Enter directory: cd sslcat_*/
3. Run install: sudo ./install-sslcat.sh

## Files
- sslcat - SSLcat binary
- sslcat.conf - Default config
- sslcat.service - systemd service
- install-sslcat.sh - Install script
- sslcat-git-hook - Git Hook script for Dokku-style deployment
- install-git-hook.sh - Git Hook installation script
- README.md - This file
EOF
    
    # 打包
    local archive_name="${PROJECT_NAME}_${VERSION}_${platform}"
    if [ "$os" = "windows" ]; then
        archive_file="${DIST_DIR}/${archive_name}.zip"
        (cd "$package_dir" && zip -q -r "../${archive_file}" .)
    else
        archive_file="${DIST_DIR}/${archive_name}.tar.gz"
        tar -czf "$archive_file" -C "$package_dir" .
    fi
    
    echo "✅ ${platform} 完成: ${archive_file}"
    rm -rf "$package_dir" "$output"
    
    return 0
}

# 构建主要平台
build_and_package "linux-amd64" "linux" "amd64"
build_and_package "darwin-amd64" "darwin" "amd64"
build_and_package "darwin-arm64" "darwin" "arm64"

# 生成 SHA256
echo "🔐 生成 SHA256 校验和..."
cd "$DIST_DIR"
if command -v sha256sum &> /dev/null; then
    sha256sum *.tar.gz *.zip 2>/dev/null > sha256sum.txt
elif command -v shasum &> /dev/null; then
    shasum -a 256 *.tar.gz *.zip 2>/dev/null > sha256sum.txt
fi
cd ..

echo "✅ 构建完成！文件在 ${DIST_DIR}/ 目录"

