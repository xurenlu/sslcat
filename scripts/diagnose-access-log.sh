#!/bin/bash

# Access Log 诊断脚本
# 用于诊断为什么 access log 不记录日志

echo "======================================"
echo "  SSLcat Access Log 诊断工具"
echo "======================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查函数
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 1. 查找 SSLcat 进程
echo "【1】检查 SSLcat 进程"
echo "-----------------------------------"
SSLCAT_PID=$(pgrep -f sslcat | head -1)
if [ -n "$SSLCAT_PID" ]; then
    check_pass "SSLcat 进程运行中 (PID: $SSLCAT_PID)"
    SSLCAT_USER=$(ps -p $SSLCAT_PID -o user= | tr -d ' ')
    SSLCAT_CWD=$(pwdx $SSLCAT_PID 2>/dev/null | awk '{print $2}')
    echo "  进程用户: $SSLCAT_USER"
    echo "  工作目录: $SSLCAT_CWD"
else
    check_fail "SSLcat 进程未运行"
    exit 1
fi
echo ""

# 2. 查找配置文件
echo "【2】查找配置文件"
echo "-----------------------------------"
CONFIG_FILE=""
if [ -n "$SSLCAT_CWD" ] && [ -f "$SSLCAT_CWD/sslcat.conf" ]; then
    CONFIG_FILE="$SSLCAT_CWD/sslcat.conf"
    check_pass "找到配置文件: $CONFIG_FILE"
elif [ -f "./sslcat.conf" ]; then
    CONFIG_FILE="./sslcat.conf"
    check_pass "找到配置文件: $CONFIG_FILE"
elif [ -f "/etc/sslcat/sslcat.conf" ]; then
    CONFIG_FILE="/etc/sslcat/sslcat.conf"
    check_pass "找到配置文件: $CONFIG_FILE"
else
    check_fail "未找到配置文件"
    echo "  请手动指定: $0 /path/to/sslcat.conf"
    exit 1
fi
echo ""

# 如果用户提供了配置文件路径作为参数
if [ -n "$1" ] && [ -f "$1" ]; then
    CONFIG_FILE="$1"
    echo "使用指定的配置文件: $CONFIG_FILE"
fi

# 3. 检查配置文件内容
echo "【3】检查 Access Log 配置"
echo "-----------------------------------"

# 检查是否启用
ACCESS_LOG_ENABLED=$(grep -o '"access_log_enabled"[[:space:]]*:[[:space:]]*[^,}]*' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*//' | tr -d ' "')
if [ "$ACCESS_LOG_ENABLED" = "true" ]; then
    check_pass "access_log_enabled: true"
elif [ "$ACCESS_LOG_ENABLED" = "false" ]; then
    check_fail "access_log_enabled: false (未启用！)"
    echo ""
    echo "【解决方案】"
    echo "修改配置文件 $CONFIG_FILE，将 access_log_enabled 改为 true："
    echo '  "access_log_enabled": true'
    exit 1
else
    check_warn "未找到 access_log_enabled 配置（默认可能未启用）"
fi

# 检查日志路径
ACCESS_LOG_PATH=$(grep -o '"access_log_path"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*"//' | tr -d '"')
if [ -n "$ACCESS_LOG_PATH" ]; then
    check_pass "access_log_path: $ACCESS_LOG_PATH"
else
    check_fail "access_log_path 未配置或为空"
    echo ""
    echo "【解决方案】"
    echo "修改配置文件 $CONFIG_FILE，添加日志路径："
    echo '  "access_log_path": "./data/access.log"'
    exit 1
fi

# 检查日志格式
ACCESS_LOG_FORMAT=$(grep -o '"access_log_format"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*"//' | tr -d '"')
if [ -n "$ACCESS_LOG_FORMAT" ]; then
    check_pass "access_log_format: $ACCESS_LOG_FORMAT"
else
    check_warn "access_log_format 未配置（将使用默认格式 nginx）"
fi
echo ""

# 4. 检查日志文件路径
echo "【4】检查日志文件"
echo "-----------------------------------"

# 处理相对路径
if [[ "$ACCESS_LOG_PATH" = /* ]]; then
    # 绝对路径
    FULL_LOG_PATH="$ACCESS_LOG_PATH"
else
    # 相对路径，基于工作目录
    if [ -n "$SSLCAT_CWD" ]; then
        FULL_LOG_PATH="$SSLCAT_CWD/$ACCESS_LOG_PATH"
    else
        FULL_LOG_PATH="$ACCESS_LOG_PATH"
    fi
fi

echo "完整日志路径: $FULL_LOG_PATH"
echo ""

# 检查日志文件是否存在
if [ -f "$FULL_LOG_PATH" ]; then
    check_pass "日志文件存在"
    
    # 检查文件大小
    FILE_SIZE=$(stat -f%z "$FULL_LOG_PATH" 2>/dev/null || stat -c%s "$FULL_LOG_PATH" 2>/dev/null)
    echo "  文件大小: $FILE_SIZE 字节"
    
    # 检查最后修改时间
    if [ "$(uname)" = "Darwin" ]; then
        LAST_MODIFIED=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FULL_LOG_PATH")
    else
        LAST_MODIFIED=$(stat -c "%y" "$FULL_LOG_PATH" | cut -d'.' -f1)
    fi
    echo "  最后修改: $LAST_MODIFIED"
    
    # 检查最近的写入
    NOW=$(date +%s)
    if [ "$(uname)" = "Darwin" ]; then
        FILE_MTIME=$(stat -f "%m" "$FULL_LOG_PATH")
    else
        FILE_MTIME=$(stat -c "%Y" "$FULL_LOG_PATH")
    fi
    AGE=$((NOW - FILE_MTIME))
    
    if [ $AGE -lt 60 ]; then
        check_pass "日志文件最近有写入（$AGE 秒前）"
    elif [ $AGE -lt 3600 ]; then
        check_warn "日志文件 $((AGE/60)) 分钟前写入，可能不活跃"
    else
        check_fail "日志文件 $((AGE/3600)) 小时前写入，似乎没有在记录"
    fi
    
    # 显示最后几行
    echo ""
    echo "最后 5 行日志："
    echo "-----------------------------------"
    tail -5 "$FULL_LOG_PATH" | while read line; do
        echo "  $line"
    done
    
else
    check_fail "日志文件不存在: $FULL_LOG_PATH"
    
    # 检查目录是否存在
    LOG_DIR=$(dirname "$FULL_LOG_PATH")
    if [ -d "$LOG_DIR" ]; then
        check_pass "日志目录存在: $LOG_DIR"
    else
        check_fail "日志目录不存在: $LOG_DIR"
        echo ""
        echo "【解决方案】创建日志目录："
        echo "  mkdir -p $LOG_DIR"
        echo "  chmod 755 $LOG_DIR"
        if [ "$SSLCAT_USER" != "$(whoami)" ]; then
            echo "  chown $SSLCAT_USER:$SSLCAT_USER $LOG_DIR"
        fi
    fi
fi
echo ""

# 5. 检查目录权限
echo "【5】检查权限"
echo "-----------------------------------"
LOG_DIR=$(dirname "$FULL_LOG_PATH")

if [ -d "$LOG_DIR" ]; then
    DIR_PERMS=$(ls -ld "$LOG_DIR" | awk '{print $1}')
    DIR_OWNER=$(ls -ld "$LOG_DIR" | awk '{print $3}')
    echo "目录权限: $DIR_PERMS (所有者: $DIR_OWNER)"
    
    if [ "$DIR_OWNER" != "$SSLCAT_USER" ]; then
        check_warn "目录所有者 ($DIR_OWNER) 与进程用户 ($SSLCAT_USER) 不匹配"
        echo ""
        echo "【解决方案】修改所有者："
        echo "  sudo chown -R $SSLCAT_USER:$SSLCAT_USER $LOG_DIR"
    else
        check_pass "目录所有者正确"
    fi
    
    # 测试写入权限
    TEST_FILE="$LOG_DIR/.test_write_$$"
    if sudo -u $SSLCAT_USER touch "$TEST_FILE" 2>/dev/null; then
        check_pass "写入权限正常"
        rm -f "$TEST_FILE"
    else
        check_fail "没有写入权限"
        echo ""
        echo "【解决方案】修复权限："
        echo "  chmod 755 $LOG_DIR"
    fi
fi

if [ -f "$FULL_LOG_PATH" ]; then
    FILE_PERMS=$(ls -l "$FULL_LOG_PATH" | awk '{print $1}')
    FILE_OWNER=$(ls -l "$FULL_LOG_PATH" | awk '{print $3}')
    echo "文件权限: $FILE_PERMS (所有者: $FILE_OWNER)"
    
    if [ "$FILE_OWNER" != "$SSLCAT_USER" ]; then
        check_warn "文件所有者与进程用户不匹配"
    fi
fi
echo ""

# 6. 检查系统日志
echo "【6】检查系统日志（最近的错误）"
echo "-----------------------------------"
if command -v journalctl &> /dev/null; then
    echo "检查 systemd 日志..."
    journalctl -u sslcat -n 20 --no-pager | grep -i "access\|log\|error" | tail -5
elif [ -f "/var/log/sslcat.log" ]; then
    echo "检查应用日志..."
    tail -20 /var/log/sslcat.log | grep -i "access\|log\|error" | tail -5
else
    check_warn "未找到系统日志"
fi
echo ""

# 7. 实时测试
echo "【7】实时测试"
echo "-----------------------------------"
echo "发送测试请求并监控日志文件..."

# 获取当前行数
if [ -f "$FULL_LOG_PATH" ]; then
    BEFORE_LINES=$(wc -l < "$FULL_LOG_PATH")
else
    BEFORE_LINES=0
fi

# 发送测试请求
echo "发送 3 个测试请求..."
for i in 1 2 3; do
    curl -s http://localhost/ > /dev/null 2>&1
    sleep 0.5
done

# 等待写入
sleep 2

# 检查新增行数
if [ -f "$FULL_LOG_PATH" ]; then
    AFTER_LINES=$(wc -l < "$FULL_LOG_PATH")
    NEW_LINES=$((AFTER_LINES - BEFORE_LINES))
    
    if [ $NEW_LINES -gt 0 ]; then
        check_pass "日志文件新增 $NEW_LINES 行，Access Log 工作正常！"
        echo ""
        echo "新增的日志："
        echo "-----------------------------------"
        tail -$NEW_LINES "$FULL_LOG_PATH" | while read line; do
            echo "  $line"
        done
    else
        check_fail "日志文件没有新增内容，Access Log 未工作"
        echo ""
        echo "【可能的原因】"
        echo "1. 配置文件修改后未重启服务"
        echo "2. 程序内部错误（查看系统日志）"
        echo "3. 配置未正确加载"
    fi
else
    check_fail "日志文件仍然不存在"
fi
echo ""

# 8. 总结和建议
echo "======================================"
echo "  诊断总结"
echo "======================================"
echo ""

if [ "$ACCESS_LOG_ENABLED" != "true" ]; then
    echo "❌ 主要问题: Access Log 未启用"
    echo ""
    echo "解决步骤："
    echo "1. 编辑配置文件: vim $CONFIG_FILE"
    echo "2. 设置: \"access_log_enabled\": true"
    echo "3. 重启服务: systemctl restart sslcat"
elif [ -z "$ACCESS_LOG_PATH" ]; then
    echo "❌ 主要问题: 日志路径未配置"
    echo ""
    echo "解决步骤："
    echo "1. 编辑配置文件: vim $CONFIG_FILE"
    echo "2. 设置: \"access_log_path\": \"./data/access.log\""
    echo "3. 创建目录: mkdir -p ./data"
    echo "4. 重启服务: systemctl restart sslcat"
elif [ ! -d "$LOG_DIR" ]; then
    echo "❌ 主要问题: 日志目录不存在"
    echo ""
    echo "解决步骤:"
    echo "  mkdir -p $LOG_DIR"
    echo "  chown $SSLCAT_USER:$SSLCAT_USER $LOG_DIR"
    echo "  systemctl restart sslcat"
elif [ $NEW_LINES -gt 0 ]; then
    echo "✅ Access Log 工作正常！"
    echo ""
    echo "日志文件: $FULL_LOG_PATH"
else
    echo "⚠️  配置看起来正确，但日志没有写入"
    echo ""
    echo "建议："
    echo "1. 重启服务: systemctl restart sslcat"
    echo "2. 查看完整日志: journalctl -u sslcat -f"
    echo "3. 检查磁盘空间: df -h"
fi
echo ""
echo "======================================"

