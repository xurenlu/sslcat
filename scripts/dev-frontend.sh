#!/bin/bash

# 前端开发服务器脚本
set -e

echo "🚀 启动前端开发服务器..."

# 进入前端目录
cd frontend

# 检查 Node.js 和 npm
if ! command -v node &> /dev/null; then
    echo "❌ Node.js 未安装，请先安装 Node.js"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "❌ npm 未安装，请先安装 npm"
    exit 1
fi

# 检查是否已安装依赖
if [ ! -d "node_modules" ]; then
    echo "📦 安装依赖..."
    npm install
fi

echo "🎨 启动 Vite 开发服务器..."
echo "📝 开发服务器地址: http://localhost:3000"
echo "🔗 API 代理: http://localhost:3000/api -> http://localhost:8443"
echo ""
echo "💡 提示:"
echo "  - 确保后端服务正在运行 (make dev 或 ./withssl)"
echo "  - 前端修改会自动热重载"
echo "  - 按 Ctrl+C 停止开发服务器"
echo ""

npm run dev
