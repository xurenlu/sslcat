#!/bin/bash

# 在测试服务器上编译 SSLcat

set -e

SERVER="root@sg2.shifen.de"
SSLCAT_DIR="/opt/sslcat"
BUILD_TYPE="${1:-cgo}"  # cgo 或 standard

echo "🔨 开始编译 SSLcat (类型: $BUILD_TYPE)..."

ssh $SERVER bash << ENDSSH
set -e

cd $SSLCAT_DIR

echo "📥 更新代码..."
if [ -d ".git" ]; then
    git pull || echo "Git pull 失败，继续使用当前代码"
else
    echo "⚠️  不是 Git 仓库，使用当前代码"
fi

echo "📦 下载依赖..."
export PATH=\$PATH:/usr/local/go/bin
go mod download
go mod tidy

echo "🏗️  构建前端..."
if [ -f "scripts/build-frontend.sh" ]; then
    bash scripts/build-frontend.sh || echo "前端构建失败，继续"
fi

echo "🔨 编译二进制文件..."
if [ "$BUILD_TYPE" = "cgo" ]; then
    # 使用 Docker 编译 CGO 版本
    if [ -f "Makefile" ]; then
        make docker-cgo-extract || {
            echo "Docker CGO 编译失败，尝试标准编译..."
            make build-linux
        }
    else
        GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o build/sslcat-linux-amd64 main.go
    fi
else
    # 标准编译
    if [ -f "Makefile" ]; then
        make build-linux
    else
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/sslcat-linux-amd64 main.go
    fi
fi

echo "✅ 编译完成"
ls -lh build/sslcat-linux-amd64* || ls -lh sslcat-linux-amd64*

ENDSSH

echo "✅ SSLcat 编译完成！"

