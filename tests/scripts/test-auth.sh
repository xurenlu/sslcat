#!/bin/bash
# 认证和基础 API 测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "认证和基础功能测试"

# 1. 测试未认证访问（应该被拒绝）
test_api "未认证访问 - 应返回401" "GET" "/api/stats" "" "401"

# 2. 测试登录
test_login

# 3. 测试获取当前用户信息
test_authenticated_api "获取当前用户" "GET" "/api/auth/me" "" "200"

# 4. 测试获取系统统计
test_authenticated_api "获取系统统计" "GET" "/api/stats" "" "200"

# 5. 测试获取配置
test_authenticated_api "获取配置" "GET" "/api/settings" "" "200"

# 6. 测试 Prometheus 指标（无需认证）
test_api "Prometheus 指标" "GET" "/../../metrics" "" "200"

# 7. 测试登出
test_authenticated_api "登出" "POST" "/api/auth/logout" "" "200"

# 8. 测试登出后访问（应该被拒绝）
test_api "登出后访问 - 应返回401" "GET" "/api/stats" "" "401"

# 重新登录以供后续测试使用
test_login

log ""
log "${GREEN}✅ 认证和基础 API 测试完成${NC}"

