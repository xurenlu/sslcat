#!/bin/bash

# 调试 MIME 类型设置
echo "=== 调试 MIME 类型设置 ==="

# 创建测试文件
TEST_DIR="/tmp/sslcat-debug"
mkdir -p "$TEST_DIR"
echo "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello World</h1></body></html>" > "$TEST_DIR/index.html"
echo "body { color: red; }" > "$TEST_DIR/style.css"

# 创建配置文件
cat > /tmp/sslcat-debug.conf << EOF
{
  "admin_prefix": "/sslcat-panel2",
  "admin_port": 9944,
  "static_sites": [
    {
      "domain": "my.localhost",
      "root": "$TEST_DIR",
      "index": "index.html",
      "enabled": true
    }
  ]
}
EOF

echo "启动服务器..."
./sslcat-test --config /tmp/sslcat-debug.conf --port 9944 &
SERVER_PID=$!

sleep 3

echo "测试 HTML 文件..."
curl -v "http://my.localhost:9944/index.html" 2>&1 | grep -i "content-type"

echo "测试 CSS 文件..."
curl -v "http://my.localhost:9944/style.css" 2>&1 | grep -i "content-type"

echo "清理..."
kill $SERVER_PID 2>/dev/null
rm -rf "$TEST_DIR"
rm -f /tmp/sslcat-debug.conf
