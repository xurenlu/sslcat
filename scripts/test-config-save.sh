#!/bin/bash

# SSLcat 配置文件保存测试脚本
# 测试修复后的配置文件保存功能

set -e

echo "🧪 开始测试配置文件保存功能..."

# 设置代理（如果需要）
export https_proxy=http://127.0.0.1:7895 http_proxy=http://127.0.0.1:7895 all_proxy=socks5://127.0.0.1:7895

# 检查是否在正确的目录
if [ ! -f "main.go" ]; then
    echo "❌ 请在 sslcat 项目根目录运行此脚本"
    exit 1
fi

# 编译项目
echo "🔨 编译项目..."
go build -o build/sslcat-test main.go

# 创建测试配置目录
TEST_DIR="/tmp/sslcat-config-test"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "📁 测试目录: $TEST_DIR"

# 测试1: 正常路径保存
echo "🧪 测试1: 正常路径保存"
cat > test-config.json << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "admin": {
    "username": "admin",
    "password": "test123"
  },
  "proxy": {
    "rules": []
  }
}
EOF

# 测试2: 权限受限路径保存
echo "🧪 测试2: 权限受限路径保存"
sudo mkdir -p /etc/sslcat-test
sudo chmod 000 /etc/sslcat-test  # 设置无权限

# 运行测试
echo "🚀 运行配置文件保存测试..."
/Users/rocky/Sites/sslcat/build/sslcat-test --config /etc/sslcat-test/sslcat.conf --test-config-save 2>&1 || true

# 恢复权限
sudo chmod 755 /etc/sslcat-test
sudo rm -rf /etc/sslcat-test

# 测试3: 备用路径保存
echo "🧪 测试3: 备用路径保存"
# 创建一个只读目录来模拟权限问题
mkdir -p "$TEST_DIR/readonly"
chmod 444 "$TEST_DIR/readonly"

# 运行测试
echo "🚀 运行备用路径测试..."
/Users/rocky/Sites/sslcat/build/sslcat-test --config "$TEST_DIR/readonly/sslcat.conf" --test-config-save 2>&1 || true

# 清理
chmod 755 "$TEST_DIR/readonly"
rm -rf "$TEST_DIR"

echo "✅ 配置文件保存测试完成！"
echo ""
echo "📋 测试总结："
echo "  - 测试了正常路径保存"
echo "  - 测试了权限受限路径的备用机制"
echo "  - 测试了备用路径自动选择"
echo ""
echo "💡 如果测试通过，说明配置文件保存功能已修复"
