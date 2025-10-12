#!/bin/bash
# 安全功能测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "安全功能测试"

# 1. 获取安全事件
test_authenticated_api "获取安全事件" "GET" "/api/security/events" "" "200"

# 2. 获取安全统计
test_authenticated_api "获取安全统计" "GET" "/api/security/stats" "" "200"

# 3. 获取被封禁的IP列表
test_authenticated_api "获取封禁IP列表" "GET" "/api/security/blocked-ips" "" "200"

# 4. 封禁测试IP
test_authenticated_api "封禁IP" "POST" "/api/security/block-ip" \
    '{"ip":"192.168.99.99"}' "200"

# 5. 解封IP
test_authenticated_api "解封IP" "POST" "/api/security/unblock" \
    '{"ip":"192.168.99.99"}' "200"

# 6. 获取TLS指纹统计
test_authenticated_api "获取TLS指纹" "GET" "/api/tls-fingerprints" "" "200"

# 7. 获取攻击统计
test_authenticated_api "获取攻击统计" "GET" "/api/security/attacks" "" "200"

# 8. 获取审计日志
test_authenticated_api "获取审计日志" "GET" "/api/audit" "" "200"

log ""
log "${GREEN}✅ 安全功能测试完成${NC}"

