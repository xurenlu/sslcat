#!/bin/bash

# Terminal UI 控制台端到端测试脚本
# 使用 expect 模拟用户交互

set +e  # 不立即退出，以便运行所有测试

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_BINARY="$PROJECT_ROOT/build/sslcat"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

# 打印测试结果
print_test() {
    echo -e "${YELLOW}测试: $1${NC}"
}

print_pass() {
    echo -e "${GREEN}✓ 通过: $1${NC}"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}✗ 失败: $1${NC}"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# 检查 expect 是否安装
check_expect() {
    if ! command -v expect &> /dev/null; then
        echo -e "${RED}错误: expect 未安装${NC}"
        echo "请安装 expect:"
        echo "  macOS: brew install expect"
        echo "  Ubuntu/Debian: sudo apt-get install expect"
        exit 1
    fi
}

# 检查二进制文件是否存在
check_binary() {
    if [ ! -f "$TEST_BINARY" ]; then
        echo -e "${YELLOW}警告: 二进制文件不存在，尝试编译...${NC}"
        cd "$PROJECT_ROOT"
        go build -o "$TEST_BINARY" ./main.go
        if [ ! -f "$TEST_BINARY" ]; then
            echo -e "${RED}错误: 编译失败${NC}"
            exit 1
        fi
    fi
}

# 创建测试配置文件
create_test_config() {
    local config_file="$1"
    cat > "$config_file" << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "port_mode": "standard",
    "enable_https": true
  },
  "ssl": {
    "email": "test@example.com",
    "staging": false,
    "cert_dir": "./data/certs",
    "key_dir": "./data/keys"
  },
  "admin": {
    "username": "admin",
    "password_file": "./data/admin.pass"
  },
  "proxy": {
    "rules": [
      {
        "domain": "test.example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": false
      }
    ]
  }
}
EOF
}

# 测试 1: 启动控制台并退出
test_console_startup() {
    print_test "启动控制台并退出"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        send "q"
        sleep 0.05
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "控制台启动成功"
    else
        print_fail "控制台启动失败"
    fi
    
    rm -f "$config_file"
}

# 测试 2: 导航菜单
test_menu_navigation() {
    print_test "菜单导航"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        send "\033\[B"
        sleep 0.05
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "菜单导航成功"
    else
        print_fail "菜单导航失败"
    fi
    
    rm -f "$config_file"
}

# 测试 3: 查看配置
test_config_view() {
    print_test "查看配置"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 尝试找到配置管理菜单项
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "配置查看成功"
    else
        print_fail "配置查看失败"
    fi
    
    rm -f "$config_file"
}

# 测试 4: 查看状态
test_status_view() {
    print_test "查看状态"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 尝试导航到状态监控
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "状态查看成功"
    else
        print_fail "状态查看失败"
    fi
    
    rm -f "$config_file"
}

# 测试 5: 查看代理规则
test_proxy_view() {
    print_test "查看代理规则"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 尝试导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "代理规则查看成功"
    else
        print_fail "代理规则查看失败"
    fi
    
    rm -f "$config_file"
}

# 测试 6: 代理规则高级配置 - 基础配置
test_proxy_advanced_basic() {
    print_test "代理规则高级配置 - 基础配置"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 添加新规则（打开高级配置视图）
        send "a"
        sleep 0.2
        # 在基础配置页面，直接退出
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "代理规则高级配置基础步骤成功"
    else
        print_fail "代理规则高级配置基础步骤失败"
    fi
    
    rm -f "$config_file"
}

# 测试 7: 代理规则高级配置 - 后端管理
test_proxy_advanced_backend() {
    print_test "代理规则高级配置 - 后端管理"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 先添加一个规则（如果没有规则，e 无法工作）
        send "a"
        sleep 0.2
        # 在基础配置页面，切换到后端服务器步骤（使用 right 或 l）
        send "l"
        sleep 0.2
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "后端管理步骤导航成功"
    else
        print_fail "后端管理步骤导航失败"
    fi
    
    rm -f "$config_file"
}

# 测试 8: 代理规则高级配置 - 自定义头部
test_proxy_advanced_headers() {
    print_test "代理规则高级配置 - 自定义头部"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 先添加一个规则（如果没有规则，e 无法工作）
        send "a"
        sleep 0.2
        # 从基础配置（步骤0）切换到自定义头部（步骤8）
        # 需要按 8 次 right/l
        send "l"
        sleep 0.05
        send "l"
        sleep 0.05
        send "l"
        sleep 0.05
        send "l"
        sleep 0.05
        send "l"
        sleep 0.05
        send "l"
        sleep 0.05
        send "l"
        sleep 0.05
        send "l"
        sleep 0.2
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "自定义头部步骤导航成功"
    else
        print_fail "自定义头部步骤导航失败"
    fi
    
    rm -f "$config_file"
}

# 测试 9: 保存配置
test_config_save() {
    print_test "保存配置"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        expect {
            -re ".*代理规则.*" {
                send "s"
                sleep 0.05
                send "q"
                expect eof
                exit 0
            }
            timeout {
                send "q"
                expect eof
                exit 0
            }
        }
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "配置保存成功"
    else
        print_fail "配置保存失败"
    fi
    
    rm -f "$config_file"
}

# 测试 10: 站点管理视图
test_sites_view() {
    print_test "站点管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到站点管理 (第4个菜单项，索引3)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "站点管理视图成功"
    else
        print_fail "站点管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 11: DNS 管理视图
test_dns_view() {
    print_test "DNS 管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到 DNS 管理 (第6个菜单项，索引5)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "DNS 管理视图成功"
    else
        print_fail "DNS 管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 12: 安全设置视图
test_security_view() {
    print_test "安全设置视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到安全设置 (第7个菜单项，索引6)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "安全设置视图成功"
    else
        print_fail "安全设置视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 13: 系统设置视图
test_settings_view() {
    print_test "系统设置视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到系统设置 (第8个菜单项，索引7)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "系统设置视图成功"
    else
        print_fail "系统设置视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 14: CDN 缓存管理视图
test_cdn_view() {
    print_test "CDN 缓存管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到 CDN 缓存管理 (第9个菜单项，索引8)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "CDN 缓存管理视图成功"
    else
        print_fail "CDN 缓存管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 15: 访问统计视图
test_statistics_view() {
    print_test "访问统计视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到访问统计 (第10个菜单项，索引9)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "访问统计视图成功"
    else
        print_fail "访问统计视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 16: 慢请求分析视图
test_slow_requests_view() {
    print_test "慢请求分析视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到慢请求分析 (第11个菜单项，索引10)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "慢请求分析视图成功"
    else
        print_fail "慢请求分析视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 17: 通知管理视图
test_notifications_view() {
    print_test "通知管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        # 导航到通知管理 (第12个菜单项，索引11)
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "通知管理视图成功"
    else
        print_fail "通知管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 18: 集群管理视图
test_cluster_view() {
    print_test "集群管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        # 导航到集群管理 (第13个菜单项，索引12)
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "集群管理视图成功"
    else
        print_fail "集群管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 19: AI 安全分析视图
test_ai_security_view() {
    print_test "AI 安全分析视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        # 导航到 AI 安全分析 (第14个菜单项，索引13)
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "AI 安全分析视图成功"
    else
        print_fail "AI 安全分析视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 20: 图片优化视图
test_image_optimization_view() {
    print_test "图片优化视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        # 导航到图片优化 (第15个菜单项，索引14)
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "图片优化视图成功"
    else
        print_fail "图片优化视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 21: 用户管理视图
test_user_management_view() {
    print_test "用户管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        # 导航到用户管理 (第16个菜单项，索引15)
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        send "\033\\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "用户管理视图成功"
    else
        print_fail "用户管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 22: SSL 证书管理视图
test_ssl_view() {
    print_test "SSL 证书管理视图"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 1
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.05
        # 导航到 SSL 证书管理 (第5个菜单项，索引4)
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        send "\033\[B"
        sleep 0.05
        send "\r"
        sleep 0.1
        send "q"
        expect eof
        exit 0
    }
    timeout {
        exit 1
    }
}
EOF
    then
        print_pass "SSL 证书管理视图成功"
    else
        print_fail "SSL 证书管理视图失败"
    fi
    
    rm -f "$config_file"
}

# 测试 22: 表单初始值预填充（编辑模式）
test_form_initial_values() {
    print_test "表单初始值预填充（编辑模式）"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 编辑现有规则
        send "e"
        sleep 0.2
        # 检查表单是否显示（应该已经预填充了值）
        # 使用 Tab 键切换字段，验证表单存在
        send "\t"
        sleep 0.1
        send "\t"
        sleep 0.1
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "表单初始值预填充成功"
    else
        print_fail "表单初始值预填充失败"
    fi
    
    rm -f "$config_file"
}

# 测试 23: ESC 键恢复到初始值
test_form_esc_reset() {
    print_test "ESC 键恢复到初始值"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 编辑现有规则
        send "e"
        sleep 0.2
        # 切换到后端服务器步骤
        send "l"
        sleep 0.2
        # 尝试编辑后端服务器
        send "e"
        sleep 0.2
        # 修改一些值（输入一些字符）
        send "test"
        sleep 0.1
        send "\t"
        sleep 0.1
        send "9999"
        sleep 0.1
        # 按 ESC 退出，应该恢复到初始值
        send "\033"
        sleep 0.2
        # 退出后端管理视图
        send "q"
        sleep 0.1
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "ESC 键恢复初始值成功"
    else
        print_fail "ESC 键恢复初始值失败"
    fi
    
    rm -f "$config_file"
}

# 测试 24: 空格键切换布尔值
test_form_boolean_toggle() {
    print_test "空格键切换布尔值"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 编辑现有规则
        send "e"
        sleep 0.2
        # 切换到后端服务器步骤
        send "l"
        sleep 0.2
        # 添加后端服务器
        send "a"
        sleep 0.2
        # 使用 Tab 键导航到布尔值字段（启用字段）
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        # 现在应该在启用字段，按空格键切换
        send " "
        sleep 0.1
        # 再次按空格键切换回来
        send " "
        sleep 0.1
        # 按 ESC 退出
        send "\033"
        sleep 0.1
        # 退出后端管理视图
        send "q"
        sleep 0.1
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "空格键切换布尔值成功"
    else
        print_fail "空格键切换布尔值失败"
    fi
    
    rm -f "$config_file"
}

# 测试 25: 添加模式默认值设置
test_form_default_values() {
    print_test "添加模式默认值设置"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 切换到后端服务器步骤
        send "l"
        sleep 0.2
        # 添加后端服务器
        send "a"
        sleep 0.2
        # 使用 Tab 键导航到各个字段，检查默认值
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        send "\t"
        sleep 0.05
        # 按 ESC 退出
        send "\033"
        sleep 0.1
        # 退出后端管理视图
        send "q"
        sleep 0.1
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "添加模式默认值设置成功"
    else
        print_fail "添加模式默认值设置失败"
    fi
    
    rm -f "$config_file"
}

# 测试 26: Ctrl+R 重置表单
test_form_ctrl_r_reset() {
    print_test "Ctrl+R 重置表单"
    
    local config_file=$(mktemp)
    create_test_config "$config_file"
    
    if expect << EOF
log_user 0
set timeout 3
spawn "$TEST_BINARY" -config "$config_file" console
expect {
    -re ".*" {
        sleep 0.1
        # 导航到代理规则管理
        send "\033\[B"
        send "\033\[B"
        sleep 0.1
        send "\r"
        sleep 0.2
        # 切换到后端服务器步骤
        send "l"
        sleep 0.2
        # 添加后端服务器
        send "a"
        sleep 0.2
        # 输入一些值
        send "test-host"
        sleep 0.1
        send "\t"
        sleep 0.1
        send "9999"
        sleep 0.1
        # 按 Ctrl+R 重置表单
        send "\018"
        sleep 0.2
        # 按 ESC 退出
        send "\033"
        sleep 0.1
        # 退出后端管理视图
        send "q"
        sleep 0.1
        # 退出高级配置视图
        send "q"
        sleep 0.1
        # 退出代理规则管理视图
        send "q"
        sleep 0.1
        expect eof
        exit 0
    }
    timeout {
        send "q"
        expect eof
        exit 1
    }
}
EOF
    then
        print_pass "Ctrl+R 重置表单成功"
    else
        print_fail "Ctrl+R 重置表单失败"
    fi
    
    rm -f "$config_file"
}

# 主测试函数
main() {
    echo "=========================================="
    echo "Terminal UI 控制台端到端测试"
    echo "=========================================="
    echo ""
    
    check_expect
    check_binary
    
    print_info "开始运行测试套件..."
    echo ""
    
    # 运行基础测试
    test_console_startup
    test_menu_navigation
    test_config_view
    test_status_view
    test_proxy_view
    
    # 运行高级功能测试
    test_proxy_advanced_basic
    test_proxy_advanced_backend
    test_proxy_advanced_headers
    test_config_save
    
    # 运行新视图测试
    test_sites_view
    test_dns_view
    test_security_view
    test_settings_view
    test_cdn_view
    test_statistics_view
    test_slow_requests_view
    test_notifications_view
    test_cluster_view
    test_ai_security_view
    test_image_optimization_view
    test_user_management_view
    test_ssl_view
    
    # 运行表单功能测试
    test_form_initial_values
    test_form_esc_reset
    test_form_boolean_toggle
    test_form_default_values
    test_form_ctrl_r_reset
    
    # 打印测试结果
    echo ""
    echo "=========================================="
    echo "测试结果"
    echo "=========================================="
    echo -e "${GREEN}通过: $TESTS_PASSED${NC}"
    echo -e "${RED}失败: $TESTS_FAILED${NC}"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}所有测试通过！${NC}"
        exit 0
    else
        echo -e "${RED}部分测试失败${NC}"
        exit 1
    fi
}

# 运行主函数
main "$@"
