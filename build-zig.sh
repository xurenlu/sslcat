#!/bin/bash

# 使用 Zig 编译兼容老版本 GLIBC 的 sslcat
# 目标：兼容 GLIBC 2.32 的 Linux amd64 二进制文件

set -e

echo "🔧 使用 Zig 编译兼容老版本 GLIBC 的 sslcat..."

# 检查 Docker 是否可用
if ! command -v docker &> /dev/null; then
    echo "❌ Docker 未安装或不可用"
    exit 1
fi

# 检查 Zig 是否在 Docker 中可用
echo "📦 检查 Zig 环境..."
docker run --rm golang:1.23.4-alpine sh -c "apk add --no-cache zig && zig version"

# 构建 Docker 镜像
echo "🏗️  构建 Zig 编译环境..."
docker build -f Dockerfile.zig -t sslcat-zig-builder .

# 从容器中提取二进制文件
echo "📤 提取编译的二进制文件..."
docker run --rm -v $(pwd):/output sslcat-zig-builder sh -c "cp /usr/local/bin/sslcat /output/sslcat-zig"

# 验证二进制文件
echo "✅ 验证编译结果..."
if [ -f "sslcat-zig" ]; then
    echo "📊 二进制文件信息："
    file sslcat-zig
    echo ""
    echo "📏 文件大小："
    ls -lh sslcat-zig
    echo ""
    echo "🔍 依赖检查："
    ldd sslcat-zig 2>/dev/null || echo "静态链接或无 ldd 工具"
    echo ""
    echo "✅ 编译完成！二进制文件：sslcat-zig"
else
    echo "❌ 编译失败，未找到二进制文件"
    exit 1
fi
