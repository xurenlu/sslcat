#!/bin/bash
# SSLcat API 测试工具库

# 加载环境变量
if [ -f "tests/.env.test" ]; then
    source tests/.env.test
fi

# 默认配置
BASE_URL="${SSLCAT_BASE_URL:-http://localhost:8080}"
ADMIN_PREFIX="${SSLCAT_ADMIN_PREFIX:-/sslcat-panel}"
ADMIN_USER="${SSLCAT_ADMIN_USER:-admin}"
ADMIN_PASS="${SSLCAT_ADMIN_PASS:-TestAdmin@2024}"
OUTPUT_DIR="${TEST_OUTPUT_DIR:-./tests/results}"

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 统计变量
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Cookie 文件
COOKIE_FILE="/tmp/sslcat-test-cookies.txt"

# 初始化
init_test() {
    mkdir -p "$OUTPUT_DIR"
    rm -f "$COOKIE_FILE"
    echo "" > "$OUTPUT_DIR/test.log"
}

# 记录日志
log() {
    echo -e "$1" | tee -a "$OUTPUT_DIR/test.log"
}

# 测试标题
test_section() {
    echo ""
    log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${BLUE}$1${NC}"
    log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# 执行测试
test_api() {
    local name=$1
    local method=$2
    local endpoint=$3
    local data=$4
    local expected_code=$5
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local url="${BASE_URL}${ADMIN_PREFIX}${endpoint}"
    local cmd="curl -s -w '\n%{http_code}' -X $method"
    
    # 添加 Cookie
    if [ -f "$COOKIE_FILE" ]; then
        cmd="$cmd -b $COOKIE_FILE -c $COOKIE_FILE"
    fi
    
    # 添加数据
    if [ -n "$data" ]; then
        cmd="$cmd -H 'Content-Type: application/json' -d '$data'"
    fi
    
    # 执行请求
    cmd="$cmd '$url'"
    response=$(eval $cmd)
    
    # 分离响应体和状态码
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | sed '$d')
    
    # 保存响应
    echo "$body" > "$OUTPUT_DIR/last-response.json"
    
    # 检查状态码
    if [ "$http_code" == "$expected_code" ]; then
        log "${GREEN}✅ PASS${NC} $name (HTTP $http_code)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log "${RED}❌ FAIL${NC} $name (Expected: $expected_code, Got: $http_code)"
        log "${YELLOW}   Response: $body${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# 测试登录
test_login() {
    test_api "登录测试" "POST" "/api/auth/login" \
        "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        "200"
}

# 测试需要认证的 API
test_authenticated_api() {
    local name=$1
    local method=$2
    local endpoint=$3
    local data=$4
    local expected_code=${5:-200}
    
    test_api "$name" "$method" "$endpoint" "$data" "$expected_code"
}

# 提取 JSON 字段
extract_json() {
    local json=$1
    local field=$2
    echo "$json" | grep -o "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed 's/.*"\([^"]*\)"/\1/'
}

# 等待服务就绪
wait_for_service() {
    local max_wait=60
    local waited=0
    
    log "${YELLOW}⏳ 等待 SSLcat 启动...${NC}"
    
    while [ $waited -lt $max_wait ]; do
        if curl -s -f "${BASE_URL}${ADMIN_PREFIX}/" > /dev/null 2>&1; then
            log "${GREEN}✅ SSLcat 已就绪${NC}"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
        printf "."
    done
    
    log "${RED}❌ SSLcat 启动超时${NC}"
    return 1
}

# 测试结果汇总
print_summary() {
    echo ""
    log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${BLUE}测试结果汇总${NC}"
    log "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "总测试数: $TOTAL_TESTS"
    log "${GREEN}通过: $PASSED_TESTS${NC}"
    
    if [ $FAILED_TESTS -gt 0 ]; then
        log "${RED}失败: $FAILED_TESTS${NC}"
        log "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        return 1
    else
        log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        log "${GREEN}🎉 所有测试通过！${NC}"
        log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        return 0
    fi
}

# 保存测试报告
save_report() {
    local report_file="$OUTPUT_DIR/test-summary.txt"
    {
        echo "SSLcat API 测试报告"
        echo "===================="
        echo "测试时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "总测试数: $TOTAL_TESTS"
        echo "通过: $PASSED_TESTS"
        echo "失败: $FAILED_TESTS"
        echo "通过率: $(awk "BEGIN {printf \"%.1f\", ($PASSED_TESTS/$TOTAL_TESTS)*100}")%"
        echo ""
        echo "详细日志: $OUTPUT_DIR/test.log"
    } > "$report_file"
    
    log "${BLUE}📄 测试报告已保存: $report_file${NC}"
}

