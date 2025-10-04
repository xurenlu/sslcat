#!/bin/bash

# SSLcat 多平台编译脚本
# 使用方法: ./scripts/build-all.sh

set -e

echo "🚀 开始编译 SSLcat 多平台二进制文件..."

# 编译参数
BUILD_TIME=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION="1.2.2"

# 编译标志
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

# 创建输出目录
mkdir -p dist

echo "📦 编译信息:"
echo "   版本: ${VERSION}"
echo "   构建时间: ${BUILD_TIME}"
echo "   Git提交: ${GIT_COMMIT}"
echo ""

# 定义编译目标
declare -A targets=(
    ["linux-amd64"]="linux amd64"
    # ["linux-arm64"]="linux arm64"
    # ["linux-arm"]="linux arm"
    # ["darwin-amd64"]="darwin amd64"
    # ["darwin-arm64"]="darwin arm64"
    # ["windows-amd64"]="windows amd64"
)

# 编译所有目标
for target in "${!targets[@]}"; do
    IFS=' ' read -r os arch <<< "${targets[$target]}"
    
    echo "🔨 正在编译 ${target}..."
    
    # 设置环境变量
    export GOOS="${os}"
    export GOARCH="${arch}"
    export CGO_ENABLED=0
    
    # 输出文件名
    if [ "${os}" = "windows" ]; then
        OUTPUT_FILE="dist/sslcat-${target}.exe"
    else
        OUTPUT_FILE="dist/sslcat-${target}"
    fi
    
    # 编译
    go build -ldflags "${LDFLAGS}" -o "${OUTPUT_FILE}" main.go
    
    # 检查编译结果
    if [ -f "${OUTPUT_FILE}" ]; then
        echo "✅ ${target} 编译成功!"
        ls -lh "${OUTPUT_FILE}"
    else
        echo "❌ ${target} 编译失败!"
    fi
    
    echo ""
done

echo "📊 编译结果汇总:"
echo "=================="
ls -lh dist/

echo ""
echo "🎯 使用方法:"
echo "   Linux AMD64: ./dist/sslcat-linux-amd64 -config sslcat.conf"
echo "   Linux ARM64: ./dist/sslcat-linux-arm64 -config sslcat.conf"
echo "   macOS AMD64: ./dist/sslcat-darwin-amd64 -config sslcat.conf"
echo "   macOS ARM64: ./dist/sslcat-darwin-arm64 -config sslcat.conf"
echo "   Windows:     dist/sslcat-windows-amd64.exe -config sslcat.conf"

echo ""
echo "🎉 所有平台编译完成!"