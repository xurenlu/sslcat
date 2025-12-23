#!/bin/bash
# 修复证书同步问题的脚本

set -e

echo "🔧 开始修复证书同步问题..."

# 1. 确保目录权限正确
echo "📁 修复目录权限..."
chown -R root:root /var/lib/sslcat/acme-cache
chmod 755 /var/lib/sslcat/acme-cache
chmod 644 /var/lib/sslcat/acme-cache/* 2>/dev/null || true

chown -R root:root /var/lib/sslcat/certs
chown -R root:root /var/lib/sslcat/keys
chmod 755 /var/lib/sslcat/certs
chmod 755 /var/lib/sslcat/keys

# 2. 清理旧的 acme-cache（强制重新申请）
echo "🧹 清理旧的 ACME 缓存..."
rm -f /var/lib/sslcat/acme-cache/*.wxside.com* 2>/dev/null || true

# 3. 重启服务
echo "🔄 重启 sslcat 服务..."
systemctl restart sslcat

# 4. 等待服务启动
sleep 3

# 5. 触发证书申请（通过访问域名）
echo "🔐 触发证书申请..."
domains=("row1.17push.com" "icon.17push.com" "log.17push.com")

for domain in "${domains[@]}"; do
    echo "  - 申请 $domain 证书..."
    curl -k -I "https://$domain" > /dev/null 2>&1 || true
    sleep 2
done

# 6. 等待证书写入
echo "⏳ 等待证书写入磁盘..."
sleep 5

# 7. 检查 acme-cache 目录
echo "📋 检查 acme-cache 目录:"
ls -lah /var/lib/sslcat/acme-cache/ | grep -E '(17push|Total)'

# 8. 同步证书到 certs 目录
echo "🔄 同步证书..."
# 这里需要调用 sslcat 的 API 来触发同步
curl -X POST "http://localhost/sslcat-panel/ssl/sync-acme" \
    -H "Cookie: session=$(cat /var/lib/sslcat/sessions/* 2>/dev/null | head -1)" \
    2>/dev/null || echo "  注意：需要手动在管理面板点击'同步ACME证书'"

echo ""
echo "✅ 修复完成！"
echo ""
echo "📌 下一步操作："
echo "1. 访问管理面板: https://17push.com/sslcat-panel/"
echo "2. 进入 SSL证书管理"
echo "3. 点击'同步ACME证书'按钮"
echo "4. 刷新页面查看证书列表"

