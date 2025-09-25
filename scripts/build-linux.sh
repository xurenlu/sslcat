#!/bin/bash

# SSLcat Linux AMD64 编译脚本
# 使用方法: ./scripts/build-linux.sh

set -e

echo "🚀 开始编译 SSLcat Linux AMD64 二进制文件..."

# 设置编译参数
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

# 编译参数
BUILD_TIME=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION="1.2.2"

# 编译标志
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

# 输出文件名
OUTPUT_FILE="sslcat-linux-amd64"

echo "📦 编译信息:"
echo "   版本: ${VERSION}"
echo "   构建时间: ${BUILD_TIME}"
echo "   Git提交: ${GIT_COMMIT}"
echo "   目标平台: Linux AMD64"
echo "   输出文件: ${OUTPUT_FILE}"
echo ""

# 开始编译
echo "🔨 正在编译..."
go build -ldflags "${LDFLAGS}" -o "${OUTPUT_FILE}" main.go

# 检查编译结果
if [ -f "${OUTPUT_FILE}" ]; then
    echo "✅ 编译成功!"
    echo ""
    echo "📊 文件信息:"
    ls -lh "${OUTPUT_FILE}"
    echo ""
    echo "🔍 文件类型:"
    file "${OUTPUT_FILE}"
    echo ""
    echo "📈 文件大小:"
    du -h "${OUTPUT_FILE}"
    echo ""
    echo "🎯 使用方法:"
    echo "   ./${OUTPUT_FILE} -config sslcat.conf"
    echo ""
    echo "📦 部署到Linux服务器:"
    echo "   1. 将 ${OUTPUT_FILE} 上传到Linux服务器"
    echo "   2. 设置执行权限: chmod +x ${OUTPUT_FILE}"
    echo "   3. 运行: ./${OUTPUT_FILE} -config sslcat.conf"
else
    echo "❌ 编译失败!"
    exit 1
fi

echo "🎉 编译完成!"
