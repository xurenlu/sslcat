#!/bin/bash

# 简化的开发启动脚本
# 使用方法: ./dev.sh [backend|frontend|both]

MODE=${1:-both}

case $MODE in
    "backend")
        echo "🔧 启动 Go 后端服务..."
        go run main.go -config sslcat-dev.conf -port 443 -host 0.0.0.0
        ;;
    "frontend")
        echo "🎨 启动 Vite 前端服务..."
        cd frontend && npm run dev
        ;;
    "both")
        echo "🚀 启动完整开发环境..."
        
        # 启动后端
        go run main.go -config sslcat-dev.conf -port 443 -host 0.0.0.0 &
        GO_PID=$!
        
        # 等待后端启动
        sleep 3
        
        # 启动前端
        cd frontend && npm run dev &
        VITE_PID=$!
        
        # 等待前端启动
        sleep 2
        
        echo "✅ 开发环境已启动"
        echo "   前端: http://localhost:9980"
        echo "   后端: http://localhost:80"
        
        # 等待中断信号
        trap 'kill $GO_PID $VITE_PID 2>/dev/null; exit' INT
        wait
        ;;
    *)
        echo "用法: $0 [backend|frontend|both]"
        echo "  backend  - 只启动 Go 后端服务"
        echo "  frontend - 只启动 Vite 前端服务"
        echo "  both     - 同时启动前后端服务 (默认)"
        exit 1
        ;;
esac
