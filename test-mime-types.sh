#!/bin/bash

# 测试静态站点 MIME 类型设置
# 使用方法: ./test-mime-types.sh

echo "=== 测试静态站点 MIME 类型设置 ==="

# 创建测试目录和文件
TEST_DIR="/tmp/sslcat-mime-test"
mkdir -p "$TEST_DIR"

# 创建各种类型的测试文件
echo "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello World</h1></body></html>" > "$TEST_DIR/index.html"
echo "body { color: red; }" > "$TEST_DIR/style.css"
echo "console.log('Hello World');" > "$TEST_DIR/script.js"
echo "Test content" > "$TEST_DIR/test.txt"
echo '{"name": "test", "value": 123}' > "$TEST_DIR/data.json"
echo "<?xml version='1.0'?><root><item>test</item></root>" > "$TEST_DIR/data.xml"

echo "创建了测试文件："
ls -la "$TEST_DIR"

echo ""
echo "=== 启动 sslcat 测试服务器 ==="

# 创建测试配置文件
cat > /tmp/sslcat-mime-test.conf << EOF
{
  "admin_prefix": "/sslcat-panel2",
  "admin_port": 9942,
  "static_sites": [
    {
      "domain": "my.localhost",
      "root": "$TEST_DIR",
      "index": "index.html",
      "enabled": true,
      "response_headers": {
        "X-Custom-Header": "Test-Value"
      }
    }
  ]
}
EOF

echo "配置文件已创建: /tmp/sslcat-mime-test.conf"

echo ""
echo "=== 启动服务器（后台运行）==="
./sslcat-test --config /tmp/sslcat-mime-test.conf --port 9942 &
SERVER_PID=$!

# 等待服务器启动
sleep 3

echo "服务器 PID: $SERVER_PID"

echo ""
echo "=== 测试各种文件的 MIME 类型 ==="

# 测试函数
test_mime() {
    local url="$1"
    local expected_type="$2"
    local description="$3"
    
    echo "测试: $description"
    echo "URL: $url"
    echo "期望类型: $expected_type"
    
    # 获取 Content-Type
    content_type=$(curl -s -I "http://my.localhost:9942$url" | grep -i "content-type" | cut -d' ' -f2- | tr -d '\r\n')
    
    if [ "$content_type" = "$expected_type" ]; then
        echo "✅ 通过: Content-Type = $content_type"
    else
        echo "❌ 失败: 期望 $expected_type, 实际 $content_type"
    fi
    echo ""
}

# 测试各种文件类型
test_mime "/" "text/html; charset=utf-8" "HTML 文件 (根路径)"
test_mime "/index.html" "text/html; charset=utf-8" "HTML 文件"
test_mime "/style.css" "text/css; charset=utf-8" "CSS 文件"
test_mime "/script.js" "application/javascript; charset=utf-8" "JavaScript 文件"
test_mime "/test.txt" "text/plain; charset=utf-8" "文本文件"
test_mime "/data.json" "application/json; charset=utf-8" "JSON 文件"
test_mime "/data.xml" "application/xml; charset=utf-8" "XML 文件"

echo "=== 清理 ==="
kill $SERVER_PID 2>/dev/null
rm -rf "$TEST_DIR"
rm -f /tmp/sslcat-mime-test.conf
rm -f sslcat-test

echo "测试完成！"
