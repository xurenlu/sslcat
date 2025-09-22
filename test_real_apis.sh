#!/bin/bash

echo "=== 真实 API 测试脚本 ==="

# 检查环境变量
echo "检查环境变量..."

required_vars=("ALIYUN_ACCESS_KEY_ID" "ALIYUN_ACCESS_KEY_SECRET" "CLOUDFLARE_API_TOKEN" "CLOUDFLARE_ZONE_ID")
missing_vars=()

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        missing_vars+=("$var")
    fi
done

if [ ${#missing_vars[@]} -gt 0 ]; then
    echo "❌ 缺少必要的环境变量: ${missing_vars[*]}"
    echo "请设置以下环境变量:"
    for var in "${missing_vars[@]}"; do
        echo "  export $var=\"your_value\""
    done
    echo ""
    echo "或者创建 .env 文件:"
    echo "  cp env.example .env"
    echo "  # 然后编辑 .env 文件，填入你的 API 密钥"
    exit 1
fi

echo "✅ 所有必要的环境变量已设置"

# 测试各个云服务商
echo ""
echo "=== 测试云服务商连接 ==="

# 测试 Cloudflare
echo ""
echo "--- 测试 Cloudflare ---"
if [ -n "$CLOUDFLARE_API_TOKEN" ] && [ -n "$CLOUDFLARE_ZONE_ID" ]; then
    echo "✅ Cloudflare 配置完整"
    echo "  API Token: ${CLOUDFLARE_API_TOKEN:0:10}..."
    echo "  Zone ID: $CLOUDFLARE_ZONE_ID"
    
    # 测试 Cloudflare API 连接
    echo "测试 Cloudflare API 连接..."
    response=$(curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID")
    
    if echo "$response" | grep -q '"success":true'; then
        echo "✅ Cloudflare API 连接成功"
        
        # 获取域名信息
        zone_name=$(echo "$response" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo "  域名: $zone_name"
        
        # 获取 DNS 记录数量
        records_response=$(curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records")
        
        record_count=$(echo "$records_response" | grep -o '"id"' | wc -l)
        echo "  DNS 记录数量: $record_count"
    else
        echo "❌ Cloudflare API 连接失败"
        echo "  响应: $response"
    fi
else
    echo "❌ Cloudflare 配置不完整"
fi

# 测试阿里云
echo ""
echo "--- 测试阿里云 ---"
if [ -n "$ALIYUN_ACCESS_KEY_ID" ] && [ -n "$ALIYUN_ACCESS_KEY_SECRET" ]; then
    echo "✅ 阿里云配置完整"
    echo "  Access Key ID: ${ALIYUN_ACCESS_KEY_ID:0:10}..."
    echo "  Access Key Secret: ${ALIYUN_ACCESS_KEY_SECRET:0:10}..."
    echo "  注意: 阿里云 API 需要复杂的签名算法，这里只验证配置完整性"
else
    echo "❌ 阿里云配置不完整"
fi

# 测试腾讯云
echo ""
echo "--- 测试腾讯云 ---"
if [ -n "$TENCENT_SECRET_ID" ] && [ -n "$TENCENT_SECRET_KEY" ]; then
    echo "✅ 腾讯云配置完整"
    echo "  Secret ID: ${TENCENT_SECRET_ID:0:10}..."
    echo "  Secret Key: ${TENCENT_SECRET_KEY:0:10}..."
    echo "  注意: 腾讯云 API 需要复杂的签名算法，这里只验证配置完整性"
else
    echo "❌ 腾讯云配置不完整"
fi

# 测试 AWS
echo ""
echo "--- 测试 AWS Route53 ---"
if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "✅ AWS 配置完整"
    echo "  Access Key ID: ${AWS_ACCESS_KEY_ID:0:10}..."
    echo "  Secret Access Key: ${AWS_SECRET_ACCESS_KEY:0:10}..."
    echo "  注意: AWS API 需要复杂的签名算法，这里只验证配置完整性"
else
    echo "❌ AWS 配置不完整"
fi

echo ""
echo "=== 测试完成 ==="
echo "✅ 所有配置检查完成"
echo ""
echo "下一步:"
echo "1. 确保所有 API 密钥都有足够的权限"
echo "2. 运行 'go run test_domain_list.go' 来测试域名列表获取功能"
echo "3. 查看日志输出了解详细的执行情况"
