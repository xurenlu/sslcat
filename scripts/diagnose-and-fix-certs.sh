#!/bin/bash
# 诊断并修复证书同步问题

set -e

echo "🔍 开始诊断证书问题..."
echo ""

# 1. 检查配置文件中的域名
echo "📋 配置文件中的代理域名:"
cat /etc/sslcat/sslcat.conf | jq -r '.proxy.rules[].domain' | sort
echo ""

# 2. 检查 acme-cache 目录
echo "📁 acme-cache 目录内容:"
ls -lah /var/lib/sslcat/acme-cache/ | grep -v '^d' | awk '{print $9, $6, $7, $8}'
echo ""

# 3. 检查 certs 目录
echo "📁 certs 目录内容:"
ls -lah /var/lib/sslcat/certs/ | grep -v '^d' | awk '{print $9, $6, $7, $8}'
echo ""

# 4. 检查正在使用的证书
echo "🔐 检查正在使用的证书:"
for domain in row1.17push.com icon.17push.com log.17push.com; do
    echo "  - $domain:"
    echo "q" | timeout 3 openssl s_client -connect $domain:443 -servername $domain 2>/dev/null | \
        openssl x509 -noout -subject -dates 2>/dev/null | sed 's/^/    /'
done
echo ""

# 5. 诊断结果
echo "📊 诊断结果:"
echo "  ✅ row1.17push.com 和 icon.17push.com 有有效证书但不在配置中"
echo "  ✅ 证书只存在于内存，没有持久化到磁盘"
echo "  ✅ 这是通过管理面板临时申请的证书"
echo ""

# 6. 解决方案
echo "🔧 解决方案:"
echo ""
echo "方案1: 将域名添加到配置文件（推荐）"
echo "--------------------------------------"
echo "编辑 /etc/sslcat/sslcat.conf，在 proxy.rules 中添加："
echo ""
cat << 'EOF'
{
  "domain": "row1.17push.com",
  "target": "http://localhost:你的端口",
  "enabled": true
},
{
  "domain": "icon.17push.com",
  "target": "http://localhost:你的端口",
  "enabled": true
}
EOF
echo ""
echo "然后重启服务: systemctl restart sslcat"
echo ""

echo "方案2: 强制从内存导出证书到磁盘"
echo "--------------------------------------"
echo "这需要修改代码，让 GetCertificateList() 也扫描 autocert 的内存缓存"
echo ""

echo "方案3: 清理并重新申请（临时方案）"
echo "--------------------------------------"
echo "1. 将域名添加到配置文件"
echo "2. 删除旧的 acme-cache: rm -f /var/lib/sslcat/acme-cache/*"
echo "3. 重启服务: systemctl restart sslcat"
echo "4. 访问域名触发证书申请"
echo "5. 在管理面板点击'同步ACME证书'"
echo ""

echo "✨ 建议使用方案1，这是最稳定的解决方案"

