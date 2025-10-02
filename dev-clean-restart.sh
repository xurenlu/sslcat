#!/bin/bash

# SSLcat 开发环境清理并重启脚本

set -e

echo "🧹 清理旧的开发环境..."

# 停止所有相关进程
echo "停止现有的 Go 和 Vite 进程..."
pkill -f "go run main.go" || true
pkill -f "vite" || true
sleep 2

# 清理前端构建缓存
echo "清理前端缓存..."
cd frontend
rm -rf node_modules/.vite
rm -rf dist
cd ..

echo ""
echo "🚀 启动开发环境..."
echo ""

# 启动后端
echo "🔧 启动 Go 后端服务 (端口 80)..."
go run main.go -config sslcat-dev.conf -port 80 -host 0.0.0.0 &
GO_PID=$!

# 等待后端启动
sleep 3

# 检查 Go 服务是否启动成功
if ! kill -0 $GO_PID 2>/dev/null; then
    echo "❌ Go 服务启动失败"
    exit 1
fi

echo "✅ Go 后端服务已启动 (PID: $GO_PID)"

# 启动前端
echo "🎨 启动 Vite 前端开发服务器 (端口 9980)..."
cd frontend
npm run dev &
VITE_PID=$!

# 等待 Vite 服务启动
sleep 3

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
echo "   ✅ 前端开发服务器: http://localhost:9980"
echo "   ✅ API 会自动代理到后端: http://localhost:80"
echo ""
echo "💡 重要提示："
echo "   - 请访问 http://localhost:9980 以使用最新的前端代码"
echo "   - 访问 http://localhost:80 会使用嵌入的旧版本（不推荐开发时使用）"
echo "   - 前端修改会自动热重载"
echo "   - 按 Ctrl+C 停止所有服务"
echo ""

# 等待用户中断
trap 'echo ""; echo "🛑 正在停止服务..."; kill $GO_PID $VITE_PID 2>/dev/null; echo "✅ 服务已停止"; exit 0' INT

# 保持脚本运行
wait

