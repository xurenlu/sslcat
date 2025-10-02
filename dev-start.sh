#!/bin/bash

# SSLcat 开发环境启动脚本
# 此脚本同时启动 Go 后端服务和 Vite 前端开发服务器

set -e

echo "🚀 启动 SSLcat 开发环境..."

# 检查是否在项目根目录
if [ ! -f "main.go" ]; then
    echo "❌ 请在项目根目录运行此脚本"
    exit 1
fi

# 检查端口是否被占用
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  端口 $port 已被占用，请先停止占用该端口的服务"
        echo "   可以使用以下命令查看占用进程："
        echo "   lsof -i :$port"
        exit 1
    fi
}

echo "🔍 检查端口占用情况..."
check_port 80
check_port 443
check_port 9980

# 启动 Go 后端服务（后台运行）
echo "🔧 启动 Go 后端服务 (端口 80/443)..."
go run main.go -config sslcat-dev.conf -port 443 -host 0.0.0.0 &
GO_PID=$!

# 等待 Go 服务启动
echo "⏳ 等待 Go 服务启动..."
sleep 3

# 检查 Go 服务是否启动成功
if ! kill -0 $GO_PID 2>/dev/null; then
    echo "❌ Go 服务启动失败"
    exit 1
fi

echo "✅ Go 后端服务已启动 (PID: $GO_PID)"

# 启动 Vite 前端开发服务器
echo "🎨 启动 Vite 前端开发服务器 (端口 9980)..."
cd frontend
npm run dev &
VITE_PID=$!

# 等待 Vite 服务启动
sleep 2

# 检查 Vite 服务是否启动成功
if ! kill -0 $VITE_PID 2>/dev/null; then
    echo "❌ Vite 服务启动失败"
    kill $GO_PID 2>/dev/null
    exit 1
fi

echo "✅ Vite 前端服务已启动 (PID: $VITE_PID)"
echo ""
echo "🎉 开发环境启动完成！"
echo ""
echo "📱 访问地址："
echo "   前端开发服务器: http://localhost:9980"
echo "   Go 后端 API:    http://localhost:80/api/"
echo "   管理面板:       http://localhost:80/sslcat-panel2/"
echo ""
echo "💡 提示："
echo "   - 前端开发时访问 http://localhost:9980"
echo "   - API 请求会自动代理到 Go 服务"
echo "   - 按 Ctrl+C 停止所有服务"
echo ""

# 等待用户中断
trap 'echo ""; echo "🛑 正在停止服务..."; kill $GO_PID $VITE_PID 2>/dev/null; echo "✅ 服务已停止"; exit 0' INT

# 保持脚本运行
wait
