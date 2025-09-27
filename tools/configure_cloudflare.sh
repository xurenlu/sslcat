#!/bin/bash

# Cloudflare DNS配置工具
# 使用方法: ./configure_cloudflare.sh <API_TOKEN> <ZONE_ID> <DOMAIN>

if [ $# -ne 3 ]; then
    echo "使用方法: $0 <API_TOKEN> <ZONE_ID> <DOMAIN>"
    echo "例如: $0 your_api_token a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 example.com"
    exit 1
fi

API_TOKEN="$1"
ZONE_ID="$2"
DOMAIN="$3"
CONFIG_FILE="./data/sslcat.conf"

echo "🔧 配置Cloudflare DNS提供商..."
echo "   域名: $DOMAIN"
echo "   Zone ID: $ZONE_ID"
echo

# 备份原配置文件
cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
echo "📁 已备份原配置文件"

# 使用jq更新配置（如果安装了jq）
if command -v jq &> /dev/null; then
    echo "🔧 使用jq更新配置..."
    jq --arg api_key "$API_TOKEN" \
       --arg zone_id "$ZONE_ID" \
       --arg domain "$DOMAIN" \
       '.ssl.dns_providers[] |= if .name == "cloudflare-dns" then 
        .api_key = $api_key | 
        .zone_id = $zone_id | 
        .enabled = true else . end' \
       "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
    
    echo "✅ 配置已更新"
    echo
    echo "📋 更新后的Cloudflare配置:"
    jq '.ssl.dns_providers[] | select(.name == "cloudflare-dns")' "$CONFIG_FILE"
else
    echo "⚠️  未安装jq，请手动更新配置文件:"
    echo "   1. 编辑 $CONFIG_FILE"
    echo "   2. 找到 cloudflare-dns 配置"
    echo "   3. 更新以下字段:"
    echo "      - api_key: \"$API_TOKEN\""
    echo "      - zone_id: \"$ZONE_ID\""
    echo "      - enabled: true"
fi

echo
echo "🧪 测试配置..."
if [ -f "./tools/test_dns_config" ]; then
    ./tools/test_dns_config
else
    echo "请先编译测试工具: go build -o tools/test_dns_config tools/test_dns_config.go"
fi


