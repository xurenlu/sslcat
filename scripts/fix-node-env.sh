#!/bin/bash

# 修复 Node.js 环境脚本
set -e

echo "🔧 修复 Node.js 环境..."

# 检查是否使用 Homebrew
if command -v brew &> /dev/null; then
    echo "📦 检测到 Homebrew，正在修复 Node.js 依赖..."
    
    # 重新安装 icu4c
    echo "🔄 重新安装 icu4c..."
    brew reinstall icu4c
    
    # 重新安装 Node.js
    echo "🔄 重新安装 Node.js..."
    brew reinstall node
    
    # 安装 pnpm
    echo "📦 安装 pnpm..."
    if ! command -v pnpm &> /dev/null; then
        npm install -g pnpm
    else
        echo "✅ pnpm 已安装"
    fi
    
    echo "✅ Node.js 环境修复完成！"
else
    echo "❌ 未检测到 Homebrew，请手动修复 Node.js 环境"
    echo "💡 建议："
    echo "   1. 重新安装 Node.js"
    echo "   2. 安装 pnpm: npm install -g pnpm"
    exit 1
fi

echo "🎉 环境修复完成，现在可以运行前端开发服务器了！"
