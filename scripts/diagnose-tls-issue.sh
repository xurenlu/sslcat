#!/bin/bash

# TLS 连接诊断脚本
# 用于诊断 sg2.shifen.de 的 TLS 连接问题

DOMAIN="sg2.shifen.de"
PROXY="socks5://127.0.0.1:7890"

echo "=== TLS 连接诊断 ==="
echo "域名: $DOMAIN"
echo "代理: $PROXY"
echo ""

# 1. 测试不使用代理的直接连接（如果服务器在国内）
echo "1. 测试不使用代理的连接..."
curl -v --connect-timeout 10 https://$DOMAIN/sslcat-panel/ssl 2>&1 | grep -E "(Connected|TLS|certificate|error|reset)" || echo "连接失败"
echo ""

# 2. 测试使用代理的详细 TLS 信息
echo "2. 测试使用代理的详细 TLS 信息..."
export ALL_PROXY=$PROXY
curl -v --connect-timeout 10 https://$DOMAIN/sslcat-panel/ssl 2>&1 | head -50
echo ""

# 3. 使用 openssl 测试 TLS 握手（不使用代理）
echo "3. 使用 openssl 测试 TLS 握手（不使用代理）..."
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>&1 | grep -E "(Certificate|Verify|error|CN=|Subject)" | head -20
echo ""

# 4. 检查证书有效性
echo "4. 检查证书有效期..."
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>&1 | openssl x509 -noout -dates 2>/dev/null || echo "无法获取证书"
echo ""

# 5. 测试不同的 TLS 版本
echo "5. 测试 TLS 1.2..."
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN -tls1_2 2>&1 | grep -E "(Protocol|Cipher|error)" | head -5
echo ""

echo "6. 测试 TLS 1.3..."
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN -tls1_3 2>&1 | grep -E "(Protocol|Cipher|error)" | head -5
echo ""

# 6. 检查域名解析
echo "7. 域名解析检查..."
nslookup $DOMAIN || dig $DOMAIN +short
echo ""

# 7. 测试端口连通性
echo "8. 测试 443 端口连通性..."
nc -zv -w 5 $DOMAIN 443 2>&1 || echo "端口可能被阻止"
echo ""

# 8. 使用 curl 测试不同的 TLS 版本
echo "9. 测试强制 TLS 1.2..."
curl --tlsv1.2 -v --connect-timeout 10 --proxy $PROXY https://$DOMAIN/sslcat-panel/ssl 2>&1 | grep -E "(Connected|TLS|error|reset)" | head -10
echo ""

echo "10. 测试强制 TLS 1.3..."
curl --tlsv1.3 -v --connect-timeout 10 --proxy $PROXY https://$DOMAIN/sslcat-panel/ssl 2>&1 | grep -E "(Connected|TLS|error|reset)" | head -10
echo ""

echo "=== 诊断完成 ==="
echo ""
echo "建议："
echo "1. 如果直接连接成功但代理连接失败，可能是 GFW 干扰"
echo "2. 如果证书错误，检查服务器端证书配置"
echo "3. 如果端口不通，检查防火墙设置"
echo "4. 检查服务器端的 sslcat 日志文件"




