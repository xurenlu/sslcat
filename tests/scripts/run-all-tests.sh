#!/bin/bash
# SSLcat 完整测试套件

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

# 开始测试
init_test

log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${GREEN}   SSLcat API 完整测试套件${NC}"
log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log ""
log "测试目标: $BASE_URL"
log "管理路径: $ADMIN_PREFIX"
log "测试时间: $(date '+%Y-%m-%d %H:%M:%S')"
log ""

# 等待服务就绪
if ! wait_for_service; then
    log "${RED}❌ 服务未就绪，测试终止${NC}"
    exit 1
fi

# 运行各个测试模块
test_modules=(
    "test-auth.sh          认证和基础API"
    "test-proxy.sh         代理规则管理"
    "test-users.sh         用户权限管理"
    "test-security.sh      安全功能"
    "test-ai-security.sh   AI安全分析"
    "test-image-opt.sh     图片优化"
)

for module_info in "${test_modules[@]}"; do
    module=$(echo "$module_info" | awk '{print $1}')
    name=$(echo "$module_info" | cut -d' ' -f2-)
    
    log ""
    log "${BLUE}▶️  运行: $name${NC}"
    
    if [ -f "$SCRIPT_DIR/$module" ]; then
        bash "$SCRIPT_DIR/$module"
    else
        log "${YELLOW}⚠️  模块不存在: $module${NC}"
    fi
done

# 额外测试
test_section "额外功能测试"

# 测试压缩功能
log "${BLUE}📦 测试压缩功能...${NC}"
response=$(curl -s -H "Accept-Encoding: gzip, br" "${BASE_URL}/test-a.local/")
if echo "$response" | grep -q "Backend A"; then
    log "${GREEN}✅ 代理响应正常${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    log "${RED}❌ 代理响应异常${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# 测试负载均衡
log "${BLUE}⚖️  测试负载均衡...${NC}"
backends_found=""
for i in {1..10}; do
    response=$(curl -s "http://test-lb.local:8080/")
    if echo "$response" | grep -q "Backend A"; then
        backends_found="${backends_found}A"
    elif echo "$response" | grep -q "Backend B"; then
        backends_found="${backends_found}B"
    elif echo "$response" | grep -q "Backend C"; then
        backends_found="${backends_found}C"
    fi
done

if echo "$backends_found" | grep -q "A" && echo "$backends_found" | grep -q "B"; then
    log "${GREEN}✅ 负载均衡工作正常（访问到多个后端）${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    log "${YELLOW}⚠️  负载均衡可能未生效（只访问到: $backends_found）${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# 测试会话保持
log "${BLUE}🍪 测试会话保持...${NC}"
cookie_jar="/tmp/lb-cookie.txt"
rm -f "$cookie_jar"

first_backend=$(curl -s -c "$cookie_jar" "http://test-lb.local:8080/" | grep -o "Backend [ABC]" | awk '{print $2}')
log "   首次访问: Backend $first_backend"

# 连续访问 5 次，应该都是同一个后端
same_backend=true
for i in {1..5}; do
    current=$(curl -s -b "$cookie_jar" "http://test-lb.local:8080/" | grep -o "Backend [ABC]" | awk '{print $2}')
    if [ "$current" != "$first_backend" ]; then
        same_backend=false
        break
    fi
done

if [ "$same_backend" = true ]; then
    log "${GREEN}✅ 会话保持工作正常${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    log "${RED}❌ 会话保持未生效${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

rm -f "$cookie_jar"

# 打印测试总结
print_summary

# 保存测试报告
save_report

# 返回结果
if [ $FAILED_TESTS -gt 0 ]; then
    exit 1
else
    exit 0
fi

