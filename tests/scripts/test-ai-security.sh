#!/bin/bash
# AI 安全分析测试（支持 POE API）

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "AI 安全分析测试"

# 检查是否配置了 POE API
POE_CONFIG_FILE="tests/poe-config.json"
if [ ! -f "$POE_CONFIG_FILE" ]; then
    log "${YELLOW}⚠️  POE 配置文件不存在，跳过 AI 测试${NC}"
    log "${YELLOW}   创建 $POE_CONFIG_FILE 并填入 API Key 以启用 AI 测试${NC}"
    return 0
fi

# 读取 POE 配置
POE_API_KEY=$(cat "$POE_CONFIG_FILE" | grep -o '"poe_api_key"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"/\1/')
POE_MODEL=$(cat "$POE_CONFIG_FILE" | grep -o '"model"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"/\1/')

if [ -z "$POE_API_KEY" ] || [ "$POE_API_KEY" == "your-poe-api-key-here" ]; then
    log "${YELLOW}⚠️  POE API Key 未配置，跳过 AI 测试${NC}"
    return 0
fi

log "${BLUE}🤖 使用 POE API 进行测试${NC}"
log "${BLUE}   Model: ${POE_MODEL:-GPT-4-Turbo}${NC}"

# 1. 获取 AI 安全配置
test_authenticated_api "获取AI安全配置" "GET" "/api/ai-security/config" "" "200"

# 2. 更新 AI 安全配置（使用 POE API）
test_authenticated_api "配置POE API" "POST" "/api/ai-security/config" \
    "{\"enabled\":true,\"api_key\":\"$POE_API_KEY\",\"api_endpoint\":\"https://api.poe.com/bot/\",\"model\":\"${POE_MODEL:-GPT-4-Turbo}\",\"language\":\"zh-CN\"}" "200"

# 3. 测试 AI 分析（需要有安全事件数据）
test_authenticated_api "触发AI分析测试" "POST" "/api/ai-security/test" "" "200"

# 4. 手动触发分析
test_authenticated_api "手动触发AI分析" "POST" "/api/ai-security/analyze-now" "" "200"

# 5. 禁用 AI（测试后清理）
test_authenticated_api "禁用AI功能" "POST" "/api/ai-security/config" \
    '{"enabled":false}' "200"

log ""
log "${GREEN}✅ AI 安全分析测试完成${NC}"

