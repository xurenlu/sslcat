#!/bin/bash

# 前端构建脚本
set -e

echo "🚀 开始构建前端项目..."

# 进入前端目录
cd frontend

# 检查 Node.js 和 pnpm
if ! command -v node &> /dev/null; then
    echo "❌ Node.js 未安装，请先安装 Node.js"
    exit 1
fi

if ! command -v yarn &> /dev/null; then
    echo "❌ yarn 未安装，请先安装 yarn:"
    echo "   npm install -g yarn"
    echo "   或使用: curl -fsSL https://yarnpkg.com/install.sh | bash"
    exit 1
fi

echo "📦 使用 yarn 安装依赖..."
yarn install

echo "🔨 构建前端项目..."
yarn run build

echo "✅ 前端构建完成！"

# 检查 dist 目录是否存在
if [ ! -d "dist" ]; then
    echo "❌ 构建失败：dist 目录不存在"
    exit 1
fi

# 显示构建结果
echo "📊 构建结果："
ls -la dist/

echo "🔗 复制前端文件到 Go 嵌入目录..."
mkdir -p ../internal/assets/frontend
cp -r dist/* ../internal/assets/frontend/

echo "🎉 前端项目构建成功！可以继续构建 Go 项目。"
