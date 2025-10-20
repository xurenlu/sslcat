#!/bin/bash

# 测试 Git Server 配置更新功能
# 验证前端更新配置时是否会同步更新主配置文件

set -e

echo "🧪 测试 Git Server 配置更新功能"
echo "================================"

# 备份当前配置
echo "📦 备份当前配置..."
cp sslcat.conf sslcat.conf.backup

# 检查当前配置
echo ""
echo "📋 当前配置："
echo "  主配置文件 runners.git.enabled:"
grep -A 10 '"runners"' sslcat.conf | grep '"enabled"' | head -1

# 启动服务
echo ""
echo "🚀 启动 SSLcat 服务（后台模式）..."
./sslcat-test --config sslcat.conf &
SSLCAT_PID=$!
echo "  PID: $SSLCAT_PID"

# 等待服务启动
sleep 3

# 测试 API：关闭 Git Server
echo ""
echo "🔄 测试 API：关闭 Git Server..."
curl -s -X PUT http://localhost:8080/sslcat-panel2/api/git-server/config \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false,
    "port": 22,
    "webhook": "",
    "default_branch": "main",
    "domain_suffix": "localhost",
    "port_range": [8000, 9000],
    "welcome_message": "Welcome",
    "auto_ssl": true,
    "ssl_email": "",
    "default_strategy": "auto",
    "build_timeout": 300,
    "auto_domain": true
  }' | jq .

sleep 1

# 检查配置文件是否已更新
echo ""
echo "✅ 检查主配置文件是否已更新..."
ENABLED_VALUE=$(grep -A 10 '"runners"' sslcat.conf | grep '"enabled"' | head -1 | grep -o 'true\|false')
echo "  runners.git.enabled = $ENABLED_VALUE"

if [ "$ENABLED_VALUE" = "false" ]; then
    echo "  ✅ 配置已同步更新！"
else
    echo "  ❌ 配置未更新（仍然是 $ENABLED_VALUE）"
fi

# 测试 API：重新开启 Git Server
echo ""
echo "🔄 测试 API：重新开启 Git Server..."
curl -s -X PUT http://localhost:8080/sslcat-panel2/api/git-server/config \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "port": 22,
    "webhook": "",
    "default_branch": "main",
    "domain_suffix": "localhost",
    "port_range": [8000, 9000],
    "welcome_message": "Welcome",
    "auto_ssl": true,
    "ssl_email": "",
    "default_strategy": "auto",
    "build_timeout": 300,
    "auto_domain": true
  }' | jq .

sleep 1

# 再次检查配置
echo ""
echo "✅ 再次检查主配置文件..."
ENABLED_VALUE=$(grep -A 10 '"runners"' sslcat.conf | grep '"enabled"' | head -1 | grep -o 'true\|false')
echo "  runners.git.enabled = $ENABLED_VALUE"

if [ "$ENABLED_VALUE" = "true" ]; then
    echo "  ✅ 配置已同步更新！"
else
    echo "  ❌ 配置未更新（仍然是 $ENABLED_VALUE）"
fi

# 停止服务
echo ""
echo "🛑 停止 SSLcat 服务..."
kill $SSLCAT_PID 2>/dev/null || true
wait $SSLCAT_PID 2>/dev/null || true

# 恢复配置
echo ""
echo "♻️  恢复原始配置..."
mv sslcat.conf.backup sslcat.conf

echo ""
echo "✅ 测试完成！"

