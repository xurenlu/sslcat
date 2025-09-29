#!/bin/bash

# 开发环境测试脚本

echo "🧪 测试 SSLcat 开发环境配置..."

# 检查必要文件
echo "📁 检查配置文件..."
files=("sslcat-dev.conf" "dev.sh" "dev-start.sh" "frontend/vite.config.ts")
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file 存在"
    else
        echo "❌ $file 不存在"
        exit 1
    fi
done

# 检查端口占用
echo ""
echo "🔍 检查端口占用..."
ports=(80 443 9980)
for port in "${ports[@]}"; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  端口 $port 已被占用"
        echo "   占用进程: $(lsof -Pi :$port -sTCP:LISTEN -t)"
    else
        echo "✅ 端口 $port 可用"
    fi
done

# 检查 Go 模块
echo ""
echo "🔧 检查 Go 环境..."
if command -v go &> /dev/null; then
    echo "✅ Go 已安装: $(go version)"
else
    echo "❌ Go 未安装"
    exit 1
fi

# 检查 Node.js 环境
echo ""
echo "📦 检查 Node.js 环境..."
if command -v node &> /dev/null; then
    echo "✅ Node.js 已安装: $(node --version)"
else
    echo "❌ Node.js 未安装"
    exit 1
fi

if command -v npm &> /dev/null; then
    echo "✅ npm 已安装: $(npm --version)"
else
    echo "❌ npm 未安装"
    exit 1
fi

# 检查前端依赖
echo ""
echo "📦 检查前端依赖..."
if [ -d "frontend/node_modules" ]; then
    echo "✅ 前端依赖已安装"
else
    echo "⚠️  前端依赖未安装，运行: cd frontend && npm install"
fi

# 检查配置文件语法
echo ""
echo "🔍 检查配置文件语法..."
if go run main.go -config sslcat-dev.conf -test 2>/dev/null; then
    echo "✅ Go 配置文件语法正确"
else
    echo "❌ Go 配置文件有错误"
fi

echo ""
echo "🎉 环境检查完成！"
echo ""
echo "📋 启动开发环境:"
echo "   方法 1: ./dev.sh"
echo "   方法 2: ./dev-start.sh"
echo "   方法 3: 手动启动"
echo ""
echo "🌐 访问地址:"
echo "   前端: http://localhost:9980"
echo "   后端: http://localhost:80"
echo "   管理: http://localhost:80/sslcat-panel/"
