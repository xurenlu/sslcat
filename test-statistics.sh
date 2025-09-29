#!/bin/bash

# 统计功能测试脚本
# 模拟一些HTTP请求来测试统计收集功能

ADMIN_PREFIX="/admin"
BASE_URL="http://localhost:8080"

echo "=== SSLcat 统计功能测试 ==="
echo "基准URL: $BASE_URL"
echo "管理前缀: $ADMIN_PREFIX"
echo ""

# 检查服务是否运行
echo "1. 检查服务状态..."
if ! curl -s "$BASE_URL$ADMIN_PREFIX/" > /dev/null; then
    echo "❌ SSLcat 服务未运行，请先启动服务"
    exit 1
fi
echo "✅ 服务运行正常"
echo ""

# 模拟一些访问请求
echo "2. 模拟访问请求..."
declare -a user_agents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    "curl/7.68.0"
    "wget/1.20.3"
)

declare -a domains=(
    "example.com"
    "test.local"
    "demo.test"
)

# 生成一些测试请求
for i in {1..50}; do
    ua="${user_agents[$((RANDOM % ${#user_agents[@]}))]}"
    domain="${domains[$((RANDOM % ${#domains[@]}))]}"
    
    # 随机生成一些不同的状态码
    if [ $((RANDOM % 10)) -lt 8 ]; then
        # 80% 成功请求
        status_code=200
    elif [ $((RANDOM % 10)) -lt 9 ]; then
        # 10% 404错误
        status_code=404
    else
        # 10% 500错误
        status_code=500
    fi
    
    echo "  -> 模拟请求 #$i (UA: ${ua:0:20}..., Domain: $domain)"
    
    # 发送请求（这里只是为了产生日志，实际的统计由中间件记录）
    curl -s -o /dev/null \
         -H "User-Agent: $ua" \
         -H "Host: $domain" \
         "$BASE_URL/" 2>/dev/null || true
    
    # 小延迟避免过快
    sleep 0.1
done
echo "✅ 完成 50 个模拟请求"
echo ""

# 等待一点时间让统计数据处理
echo "3. 等待统计数据处理..."
sleep 2
echo ""

# 测试统计API
echo "4. 测试统计API..."

# 获取配置
echo "  -> 获取统计配置"
curl -s "$BASE_URL$ADMIN_PREFIX/api/statistics/config" | jq '.' 2>/dev/null || echo "配置API调用"

echo ""

# 获取时间键
echo "  -> 获取小时维度时间键"
curl -s "$BASE_URL$ADMIN_PREFIX/api/statistics/time-keys?dimension=hour" | jq '.time_keys[:3]' 2>/dev/null || echo "时间键API调用"

echo ""

# 获取统计数据
echo "  -> 获取当前小时统计数据"
curl -s "$BASE_URL$ADMIN_PREFIX/api/statistics?dimension=hour&top_n=10" | jq '.data | {dimension, time_key, domain_stats, top_ips: .top_ips[:3], top_user_agents: .top_user_agents[:3]}' 2>/dev/null || echo "统计数据API调用"

echo ""

# 获取天统计
echo "  -> 获取当前天统计数据"
curl -s "$BASE_URL$ADMIN_PREFIX/api/statistics?dimension=day&top_n=5" | jq '.data | {dimension, time_key, domain_stats}' 2>/dev/null || echo "天统计API调用"

echo ""
echo "=== 测试完成 ==="
echo ""
echo "📊 访问统计页面: $BASE_URL$ADMIN_PREFIX/statistics"
echo "🔧 API端点:"
echo "   - 统计数据: $BASE_URL$ADMIN_PREFIX/api/statistics"
echo "   - 配置管理: $BASE_URL$ADMIN_PREFIX/api/statistics/config"
echo "   - 时间键列表: $BASE_URL$ADMIN_PREFIX/api/statistics/time-keys"
echo ""
echo "注意：统计功能使用漏斗模型，需要一定的访问量和时间跨度才能看到高频访问者排行榜"
