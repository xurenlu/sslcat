#!/bin/bash
# 图片优化测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "图片优化测试"

# 1. 获取图片优化配置
test_authenticated_api "获取图片优化配置" "GET" "/api/image-optimization/config" "" "200"

# 2. 启用图片优化
test_authenticated_api "启用图片优化" "POST" "/api/image-optimization/config" \
    '{"config":{"enabled":true,"auto_webp":true,"webp_quality":80,"allow_resize":true}}' "200"

# 3. 获取图片优化统计
test_authenticated_api "获取优化统计" "GET" "/api/image-optimization/stats" "" "200"

# 4. 测试图片请求优化（需要实际的图片）
if [ -f "tests/images/test-large.jpg" ]; then
    log "${BLUE}📷 测试图片优化...${NC}"
    
    # 上传测试图片到后端（假设有静态文件服务）
    # 然后通过代理请求并检查是否被优化
    
    # 测试原始图片
    response=$(curl -s -I "http://localhost:8080/images/test-large.jpg")
    content_type=$(echo "$response" | grep -i "Content-Type:" | awk '{print $2}')
    log "   原始 Content-Type: $content_type"
    
    # 测试 WebP 转换
    response=$(curl -s -I -H "Accept: image/webp,*/*" "http://localhost:8080/images/test-large.jpg")
    content_type=$(echo "$response" | grep -i "Content-Type:" | awk '{print $2}')
    optimized=$(echo "$response" | grep -i "X-Image-Optimized:")
    
    if echo "$content_type" | grep -q "webp"; then
        log "${GREEN}   ✅ WebP 转换成功${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        log "${YELLOW}   ⚠️  WebP 转换未生效（可能图片路径不在优化范围）${NC}"
    fi
    
    # 测试尺寸调整
    response=$(curl -s -I "http://localhost:8080/images/test-large.jpg?width=400")
    log "   尺寸调整请求: HTTP $(echo "$response" | head -n1 | awk '{print $2}')"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 2))
else
    log "${YELLOW}⚠️  测试图片不存在，跳过图片优化实际测试${NC}"
fi

# 5. 清空图片缓存
test_authenticated_api "清空图片缓存" "POST" "/api/image-optimization/cache/clear" "" "200"

# 6. 禁用图片优化（测试后清理）
test_authenticated_api "禁用图片优化" "POST" "/api/image-optimization/config" \
    '{"config":{"enabled":false}}' "200"

log ""
log "${GREEN}✅ 图片优化测试完成${NC}"

