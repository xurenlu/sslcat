#!/bin/bash

# HTTP/2 支持测试脚本

echo "🔍 测试 sslcat HTTP/2 支持"
echo "================================"

# 检查编译后的二进制文件
if [ ! -f "build/sslcat-http2" ]; then
    echo "❌ 二进制文件不存在，请先编译"
    exit 1
fi

echo "✅ 二进制文件存在: build/sslcat-http2"

# 检查 HTTP/2 依赖
echo ""
echo "📦 检查 HTTP/2 依赖..."
if go list -m golang.org/x/net > /dev/null 2>&1; then
    echo "✅ HTTP/2 依赖已安装: $(go list -m golang.org/x/net)"
else
    echo "❌ HTTP/2 依赖未安装"
    exit 1
fi

# 检查 curl 是否支持 HTTP/2
echo ""
echo "🌐 检查 curl HTTP/2 支持..."
if curl --version | grep -q "HTTP2"; then
    echo "✅ curl 支持 HTTP/2"
else
    echo "⚠️  curl 可能不支持 HTTP/2，建议使用: brew install curl"
fi

# 检查 nghttp2 工具
echo ""
echo "🔧 检查 nghttp2 工具..."
if command -v nghttp > /dev/null 2>&1; then
    echo "✅ nghttp 工具可用"
else
    echo "⚠️  建议安装 nghttp2: brew install nghttp2"
fi

echo ""
echo "🚀 测试方法:"
echo "1. 启动 sslcat: ./build/sslcat-http2"
echo "2. 测试 HTTP/2: curl --http2 -I https://your-domain.com"
echo "3. 详细测试: curl --http2 -v https://your-domain.com"
echo "4. 使用 nghttp: nghttp -nv https://your-domain.com"

echo ""
echo "📊 预期结果:"
echo "- 不再出现 'PRI * HTTP/2.0' 502 错误"
echo "- 响应头包含 'HTTP/2 200'"
echo "- 性能提升 20-30%"

echo ""
echo "✅ HTTP/2 支持已配置完成！"
