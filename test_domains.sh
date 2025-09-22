#!/bin/bash

echo "=== 域名列表获取测试 ==="

# 检查环境变量
echo "检查环境变量..."

# 检查必要的环境变量
required_vars=("ALIYUN_ACCESS_KEY_ID" "ALIYUN_ACCESS_KEY_SECRET" "CLOUDFLARE_API_TOKEN" "CLOUDFLARE_ZONE_ID")
missing_vars=()

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        missing_vars+=("$var")
    fi
done

if [ ${#missing_vars[@]} -gt 0 ]; then
    echo "警告: 以下环境变量未设置: ${missing_vars[*]}"
    echo "请检查 .env 文件或设置相应的环境变量"
    echo ""
    echo "示例 .env 文件内容:"
    echo "ALIYUN_ACCESS_KEY_ID=your_aliyun_access_key_id"
    echo "ALIYUN_ACCESS_KEY_SECRET=your_aliyun_access_key_secret"
    echo "CLOUDFLARE_API_TOKEN=your_cloudflare_api_token"
    echo "CLOUDFLARE_ZONE_ID=your_cloudflare_zone_id"
    echo "TENCENT_SECRET_ID=your_tencent_secret_id"
    echo "TENCENT_SECRET_KEY=your_tencent_secret_key"
    echo "AWS_ACCESS_KEY_ID=your_aws_access_key_id"
    echo "AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key"
else
    echo "✓ 所有必要的环境变量已设置"
fi

echo ""
echo "=== 测试说明 ==="
echo "1. 请确保已设置相应的云服务商API密钥"
echo "2. 运行 'go run test_domain_list.go' 来测试域名列表获取功能"
echo "3. 或者运行 'go test -v ./internal/ssl' 来运行单元测试"
echo ""
echo "=== 可用的云服务商 ==="
echo "- 阿里云 (Aliyun)"
echo "- Cloudflare"
echo "- 腾讯云 (Tencent)"
echo "- AWS Route53"
echo "- GoDaddy"
echo "- 自定义DNS服务商"
echo ""
echo "测试完成！"
