#!/bin/bash
# 代理规则管理测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "代理规则管理测试"

# 1. 获取代理规则列表
test_authenticated_api "获取代理规则列表" "GET" "/api/proxy/rules" "" "200"

# 2. 添加代理规则
test_authenticated_api "添加代理规则" "POST" "/api/proxy/rule" \
    '{"domain":"test-new.local","target":"backend-a","port":80,"enabled":true}' "200"

# 3. 获取单个代理规则
test_authenticated_api "获取单个规则" "GET" "/api/proxy/rule?domain=test-new.local" "" "200"

# 4. 更新代理规则
test_authenticated_api "更新代理规则" "PUT" "/api/proxy/rule" \
    '{"domain":"test-new.local","target":"backend-b","port":80,"enabled":false}' "200"

# 5. 删除代理规则
test_authenticated_api "删除代理规则" "DELETE" "/api/proxy-rules/delete?domain=test-new.local" "" "200"

# 6. 测试负载均衡配置
test_authenticated_api "测试负载均衡规则" "GET" "/api/proxy/rule?domain=test-lb.local" "" "200"

log ""
log "${GREEN}✅ 代理规则测试完成${NC}"

