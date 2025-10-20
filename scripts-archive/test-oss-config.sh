#!/bin/bash

# SSLcat OSS 配置测试脚本
# 用于验证阿里云OSS配置是否正确

echo "🔧 SSLcat OSS 配置测试"
echo "========================="

# 检查必要的环境变量
check_env_var() {
    local var_name=$1
    local var_value=$2
    
    if [ -z "$var_value" ]; then
        echo "❌ $var_name 未设置"
        return 1
    else
        echo "✅ $var_name 已设置"
        return 0
    fi
}

echo ""
echo "📋 检查环境变量配置："
echo "---------------------"

# 检查GitHub Secrets（这些在GitHub Actions中会自动设置）
echo "GitHub Actions 环境变量检查："
echo "  GITHUB_REF_NAME: ${GITHUB_REF_NAME:-未设置}"
echo "  GITHUB_RUN_ID: ${GITHUB_RUN_ID:-未设置}"

echo ""
echo "阿里云OSS配置检查："
echo "  ALIYUN_ACCESS_KEY_ID: ${ALIYUN_ACCESS_KEY_ID:+已设置}"
echo "  ALIYUN_ACCESS_KEY_SECRET: ${ALIYUN_ACCESS_KEY_SECRET:+已设置}"
echo "  ALIYUN_OSS_BUCKET: ${ALIYUN_OSS_BUCKET:-未设置}"
echo "  ALIYUN_OSS_ENDPOINT: ${ALIYUN_OSS_ENDPOINT:-未设置}"

echo ""
echo "🧪 测试OSS连接（如果配置了环境变量）："
echo "-----------------------------------"

if [ -n "$ALIYUN_ACCESS_KEY_ID" ] && [ -n "$ALIYUN_ACCESS_KEY_SECRET" ]; then
    # 安装ossutil
    if ! command -v ossutil &> /dev/null; then
        echo "📥 下载并安装 ossutil..."
        wget -q https://gosspublic.alicdn.com/ossutil/1.7.18/ossutil64
        chmod +x ossutil64
        sudo mv ossutil64 /usr/local/bin/ossutil
    fi
    
    # 配置ossutil
    echo "⚙️ 配置 ossutil..."
    ossutil config -e "$ALIYUN_OSS_ENDPOINT" \
                   -i "$ALIYUN_ACCESS_KEY_ID" \
                   -k "$ALIYUN_ACCESS_KEY_SECRET" \
                   --language EN
    
    # 测试连接
    echo "🔗 测试OSS连接..."
    if ossutil ls oss://"$ALIYUN_OSS_BUCKET"/ --max-keys 1 > /dev/null 2>&1; then
        echo "✅ OSS连接成功！"
        
        # 列出bucket内容
        echo ""
        echo "📁 当前OSS Bucket内容："
        echo "----------------------"
        ossutil ls oss://"$ALIYUN_OSS_BUCKET"/ --max-keys 10
    else
        echo "❌ OSS连接失败，请检查配置"
    fi
else
    echo "⚠️ 阿里云OSS环境变量未设置，跳过连接测试"
    echo "   请在GitHub仓库的Settings > Secrets中配置："
    echo "   - ALIYUN_ACCESS_KEY_ID"
    echo "   - ALIYUN_ACCESS_KEY_SECRET"
    echo "   - ALIYUN_OSS_BUCKET"
    echo "   - ALIYUN_OSS_ENDPOINT"
fi

echo ""
echo "📝 下一步："
echo "----------"
echo "1. 确保GitHub仓库已配置所有必要的Secrets"
echo "2. 推送标签 v1.3.13-rc10 已触发workflow"
echo "3. 查看GitHub Actions运行状态："
echo "   https://github.com/xurenlu/sslcat/actions"
echo "4. 成功后可访问OSS下载地址："
echo "   https://sslcat-releases.oss-cn-hangzhou.aliyuncs.com/releases/v1.3.13-rc10/"

echo ""
echo "🎉 配置完成！"
