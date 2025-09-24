#!/bin/bash

# 完整构建脚本（前端 + 后端）
set -e

echo "🚀 开始完整构建流程..."

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "📁 项目根目录: $PROJECT_ROOT"

# 1. 构建前端
echo "🎨 第1步：构建前端..."
cd "$PROJECT_ROOT"
bash scripts/build-frontend.sh

# 2. 构建后端
echo "🏗️ 第2步：构建后端..."
cd "$PROJECT_ROOT"

# 设置 Go 构建参数
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# 构建 Go 项目
echo "🔨 编译 Go 项目..."
go build -ldflags "-w -s" -o withssl-linux-amd64 .

# 也构建当前系统版本
unset GOOS
unset GOARCH
go build -ldflags "-w -s" -o withssl .

echo "✅ 构建完成！"

# 显示构建结果
echo "📊 构建结果："
ls -la withssl*

echo "🎉 完整构建流程完成！"
echo ""
echo "📝 使用说明："
echo "- withssl: 当前系统可执行文件"
echo "- withssl-linux-amd64: Linux x64 可执行文件"
echo "- 前端文件已嵌入到可执行文件中"
echo ""
echo "🚀 现在可以直接运行: ./withssl"
