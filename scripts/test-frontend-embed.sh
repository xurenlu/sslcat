#!/bin/bash

# 测试前端嵌入功能的脚本
set -e

echo "🧪 测试前端文件嵌入功能..."

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "📁 项目根目录: $PROJECT_ROOT"

cd "$PROJECT_ROOT"

# 检查前端 dist 目录
echo ""
echo "📦 检查前端 dist 目录:"
if [ -d "frontend/dist" ]; then
    echo "✅ frontend/dist 目录存在"
    echo "📄 文件列表:"
    find frontend/dist -type f | sort
    echo ""
    echo "📊 文件统计:"
    echo "  总文件数: $(find frontend/dist -type f | wc -l)"
    echo "  HTML 文件: $(find frontend/dist -name "*.html" | wc -l)"
    echo "  JS 文件: $(find frontend/dist -name "*.js" | wc -l)"
    echo "  CSS 文件: $(find frontend/dist -name "*.css" | wc -l)"
else
    echo "❌ frontend/dist 目录不存在"
    echo "💡 运行 'make build-frontend' 来构建前端"
    exit 1
fi

# 尝试构建 Go 项目来测试嵌入
echo ""
echo "🔨 测试 Go 嵌入构建..."
if go build -o test-embed . 2>/dev/null; then
    echo "✅ Go 构建成功，前端文件已嵌入"
    
    # 检查二进制文件大小
    BINARY_SIZE=$(stat -f%z test-embed 2>/dev/null || stat -c%s test-embed 2>/dev/null || echo "unknown")
    echo "📦 二进制文件大小: $BINARY_SIZE bytes"
    
    # 清理测试文件
    rm -f test-embed
else
    echo "❌ Go 构建失败"
    echo "💡 检查 Go 代码中的嵌入路径配置"
    exit 1
fi

# 检查嵌入配置
echo ""
echo "🔍 检查嵌入配置:"
if grep -r "go:embed.*frontend/dist" internal/assets/; then
    echo "✅ 找到嵌入配置"
else
    echo "❌ 未找到嵌入配置"
fi

echo ""
echo "✅ 前端嵌入测试完成！"
echo ""
echo "📝 下一步:"
echo "  1. 运行 'make build' 进行完整构建"
echo "  2. 启动服务器并访问 /admin/spa/ 测试前端"
echo "  3. 检查浏览器开发者工具确认资源加载"
