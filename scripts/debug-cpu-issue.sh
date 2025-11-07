#!/bin/bash
# 快速诊断 sslcat CPU 问题

set -e

echo "=========================================="
echo "SSLcat CPU 问题诊断"
echo "=========================================="
echo ""

# 1. 检查进程 CPU 使用率
echo "[1] 检查进程 CPU 使用率..."
PID=$(pgrep -x sslcat || echo "")
if [ -z "$PID" ]; then
    echo "❌ 未找到 sslcat 进程"
    exit 1
fi

echo "进程 PID: $PID"
for i in {1..5}; do
    CPU=$(ps -p "$PID" -o %cpu --no-headers | tr -d ' ')
    echo "  CPU 使用率: ${CPU}%"
    sleep 1
done
echo ""

# 2. 检查 Goroutine 数量
echo "[2] 检查 Goroutine 数量..."
if command -v curl &> /dev/null; then
    GOROUTINE_COUNT=$(curl -s "http://localhost/debug/pprof/goroutine?debug=1" 2>/dev/null | grep -c "^goroutine " || echo "0")
    echo "  Goroutine 数量: $GOROUTINE_COUNT"
    if [ "$GOROUTINE_COUNT" -gt 500 ]; then
        echo "  ⚠️  警告: Goroutine 数量过多，可能存在泄露"
    fi
else
    echo "  ⚠️  无法检查（需要 curl）"
fi
echo ""

# 3. 检查 Runner 应用数量
echo "[3] 检查 Runner 应用数量..."
CONFIG_FILE="/opt/sslcat/data/sslcat.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="/etc/sslcat/sslcat.conf"
fi
if [ -f "$CONFIG_FILE" ]; then
    RUNNER_COUNT=$(grep -o '"enabled".*true' "$CONFIG_FILE" | grep -c runner || echo "0")
    echo "  Runner 应用数量: $RUNNER_COUNT"
    if [ "$RUNNER_COUNT" -gt 10 ]; then
        echo "  ⚠️  警告: Runner 应用过多，每个应用都有 1 秒的日志检查 ticker"
    fi
else
    echo "  ⚠️  无法找到配置文件"
fi
echo ""

# 4. 检查健康检查配置
echo "[4] 检查健康检查配置..."
if [ -f "$CONFIG_FILE" ]; then
    HEALTH_CHECK_ENABLED=$(grep -o '"health_check_enabled".*true' "$CONFIG_FILE" | wc -l || echo "0")
    HEALTH_CHECK_INTERVAL=$(grep -o '"health_check_interval".*[0-9]' "$CONFIG_FILE" | grep -o '[0-9]*' | head -1 || echo "")
    echo "  启用健康检查的规则数: $HEALTH_CHECK_ENABLED"
    if [ -n "$HEALTH_CHECK_INTERVAL" ]; then
        echo "  健康检查间隔: ${HEALTH_CHECK_INTERVAL}秒"
        if [ "$HEALTH_CHECK_INTERVAL" -lt 60 ]; then
            echo "  ⚠️  警告: 健康检查间隔过短（建议 ≥ 60 秒）"
        fi
    fi
fi
echo ""

# 5. 检查 DNS 验证状态
echo "[5] 检查 DNS 验证状态..."
if [ -f "$CONFIG_FILE" ]; then
    DNS_VERIFY_COUNT=$(grep -c "dns_verify\|dns_provider" "$CONFIG_FILE" 2>/dev/null || echo "0")
    echo "  DNS 验证配置数: $DNS_VERIFY_COUNT"
    if [ "$DNS_VERIFY_COUNT" -gt 5 ]; then
        echo "  ⚠️  警告: DNS 验证配置较多，每个都有 3-15 秒的 ticker"
    fi
fi
echo ""

# 6. 生成 CPU profile（30秒）
echo "[6] 生成 CPU Profile（30秒）..."
if command -v curl &> /dev/null; then
    echo "  正在收集 CPU Profile，请等待 30 秒..."
    curl -s "http://localhost/debug/pprof/profile?seconds=30" > /tmp/cpu.prof 2>/dev/null || echo "  ⚠️  无法收集 CPU Profile"
    if [ -f /tmp/cpu.prof ]; then
        FILE_SIZE=$(ls -lh /tmp/cpu.prof | awk '{print $5}')
        echo "  ✓ CPU Profile 已保存: /tmp/cpu.prof ($FILE_SIZE)"
        echo "  使用以下命令分析:"
        echo "    go tool pprof -top /tmp/cpu.prof"
    fi
else
    echo "  ⚠️  无法生成（需要 curl）"
fi
echo ""

# 7. 检查 top CPU 占用函数
echo "[7] 分析 CPU Profile..."
if [ -f /tmp/cpu.prof ] && command -v go &> /dev/null; then
    echo "  Top 10 CPU 占用函数:"
    go tool pprof -top /tmp/cpu.prof 2>/dev/null | head -20 || echo "  ⚠️  无法分析"
else
    echo "  ⚠️  跳过（需要 go tool）"
fi
echo ""

echo "=========================================="
echo "诊断完成"
echo "=========================================="
echo ""
echo "建议优化方向:"
echo "1. 如果 Runner 应用过多，考虑增加日志检查间隔（从1秒改为2-3秒）"
echo "2. 如果健康检查间隔过短，建议设置为 ≥ 60 秒"
echo "3. 检查是否有 goroutine 泄露"
echo "4. 查看 CPU Profile 找出热点函数"

