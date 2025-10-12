#!/bin/bash
# 用户和权限管理测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "用户和权限管理测试"

# 1. 获取用户列表
test_authenticated_api "获取用户列表" "GET" "/api/users" "" "200"

# 2. 添加普通用户
test_authenticated_api "添加普通用户" "POST" "/api/users/add" \
    '{"username":"testuser","password":"TestUser@123","role":"user"}' "200"

# 3. 修改用户密码
test_authenticated_api "修改用户密码" "POST" "/api/auth/change-password" \
    '{"old_password":"TestAdmin@2024","new_password":"NewAdmin@2024"}' "200"

# 4. 再次修改回原密码
test_authenticated_api "恢复原密码" "POST" "/api/auth/change-password" \
    '{"old_password":"NewAdmin@2024","new_password":"TestAdmin@2024"}' "200"

# 5. 删除测试用户
test_authenticated_api "删除测试用户" "POST" "/api/users/delete" \
    '{"username":"testuser"}' "200"

# 6. 获取用户日志
test_authenticated_api "获取用户日志" "GET" "/api/users/logs" "" "200"

log ""
log "${GREEN}✅ 用户管理测试完成${NC}"

