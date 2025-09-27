#!/bin/bash

# Cloudflare Zone ID 获取工具
# 使用方法: ./get_cloudflare_zone_id.sh <API_TOKEN> <DOMAIN>

if [ $# -ne 2 ]; then
    echo "使用方法: $0 <API_TOKEN> <DOMAIN>"
    echo "例如: $0 your_api_token example.com"
    exit 1
fi

API_TOKEN="$1"
DOMAIN="$2"

echo "🔍 正在获取域名 $DOMAIN 的 Cloudflare Zone ID..."
echo

# 使用Cloudflare API获取Zone信息
response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
     -H "Authorization: Bearer $API_TOKEN" \
     -H "Content-Type: application/json")

# 检查响应
if echo "$response" | grep -q '"success":true'; then
    zone_id=$(echo "$response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    zone_name=$(echo "$response" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -n "$zone_id" ]; then
        echo "✅ 找到Zone信息:"
        echo "   域名: $zone_name"
        echo "   Zone ID: $zone_id"
        echo
        echo "📋 配置SSLcat时使用:"
        echo "   Zone ID: $zone_id"
    else
        echo "❌ 未找到Zone ID"
    fi
else
    echo "❌ API请求失败"
    echo "响应: $response"
    echo
    echo "💡 可能的原因:"
    echo "   - API Token无效或权限不足"
    echo "   - 域名不在您的Cloudflare账户中"
    echo "   - 网络连接问题"
fi


