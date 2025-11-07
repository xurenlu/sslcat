#!/bin/bash
# 长时间运行 CPU 问题诊断脚本
# 用于诊断 sslcat 运行一段时间后 CPU 占用高的问题

set -e

echo "=========================================="
echo "SSLcat 长时间运行 CPU 问题诊断"
echo "=========================================="
echo ""

PID=$(pgrep -x sslcat || echo "")
if [ -z "$PID" ]; then
    echo "❌ 未找到 sslcat 进程"
    exit 1
fi

echo "进程 PID: $PID"
echo "运行时间: $(ps -p $PID -o etime --no-headers | tr -d ' ')"
echo ""

# 1. 检查 Goroutine 数量（通过 API）
echo "[1] 检查 Goroutine 数量..."
# 尝试通过 API 获取（需要认证）
GOROUTINE_COUNT=$(curl -s "http://localhost/debug/pprof/goroutine?debug=1" 2>/dev/null | grep -c "^goroutine " || echo "0")
if [ "$GOROUTINE_COUNT" = "0" ]; then
    # 如果 API 不可用，尝试通过系统调用估算
    THREAD_COUNT=$(ps -p $PID -o nlwp --no-headers | tr -d ' ')
    echo "  线程数: $THREAD_COUNT (Goroutine 数量通常 ≈ 线程数 × 10-50)"
else
    echo "  Goroutine 数量: $GOROUTINE_COUNT"
    if [ "$GOROUTINE_COUNT" -gt 500 ]; then
        echo "  ⚠️  警告: Goroutine 数量过多，可能存在泄露"
    fi
fi
echo ""

# 2. 检查内存使用和 GC
echo "[2] 检查内存使用..."
MEM_INFO=$(ps -p $PID -o %mem,rss,vsz --no-headers)
MEM_PERCENT=$(echo $MEM_INFO | awk '{print $1}')
RSS=$(echo $MEM_INFO | awk '{print $2}')
VSZ=$(echo $MEM_INFO | awk '{print $3}')
echo "  内存占用: ${MEM_PERCENT}%"
echo "  实际内存 (RSS): $(($RSS / 1024)) MB"
echo "  虚拟内存 (VSZ): $(($VSZ / 1024)) MB"

# 检查内存增长趋势
if [ -f /tmp/sslcat_mem_baseline ]; then
    BASELINE_RSS=$(cat /tmp/sslcat_mem_baseline)
    MEM_GROWTH=$((RSS - BASELINE_RSS))
    if [ $MEM_GROWTH -gt 10485760 ]; then  # 10MB
        echo "  ⚠️  警告: 内存增长超过 10MB，可能存在内存泄露"
    fi
else
    echo $RSS > /tmp/sslcat_mem_baseline
    echo "  已记录基线内存: $(($RSS / 1024)) MB"
fi
echo ""

# 3. 检查文件描述符
echo "[3] 检查文件描述符..."
FD_COUNT=$(ls /proc/$PID/fd 2>/dev/null | wc -l || echo "0")
echo "  文件描述符数量: $FD_COUNT"
if [ "$FD_COUNT" -gt 1000 ]; then
    echo "  ⚠️  警告: 文件描述符数量过多，可能存在连接泄露"
fi
echo ""

# 4. 检查 CPU 使用率趋势
echo "[4] 检查 CPU 使用率（10秒采样）..."
CPU_SUM=0
CPU_COUNT=0
for i in {1..10}; do
    CPU=$(ps -p $PID -o %cpu --no-headers | tr -d ' ')
    CPU_SUM=$(echo "$CPU_SUM + $CPU" | bc)
    CPU_COUNT=$((CPU_COUNT + 1))
    sleep 1
done
AVG_CPU=$(echo "scale=2; $CPU_SUM / $CPU_COUNT" | bc)
echo "  平均 CPU 使用率: ${AVG_CPU}%"

if [ $(echo "$AVG_CPU > 10" | bc) -eq 1 ]; then
    echo "  ⚠️  警告: CPU 使用率较高"
fi
echo ""

# 5. 检查连接数
echo "[5] 检查网络连接数..."
ESTABLISHED=$(netstat -an 2>/dev/null | grep ESTABLISHED | grep ":$PID" | wc -l || ss -an 2>/dev/null | grep ESTAB | wc -l || echo "0")
TIME_WAIT=$(netstat -an 2>/dev/null | grep TIME_WAIT | grep ":$PID" | wc -l || ss -an 2>/dev/null | grep TIME-WAIT | wc -l || echo "0")
echo "  ESTABLISHED 连接: $ESTABLISHED"
echo "  TIME_WAIT 连接: $TIME_WAIT"
if [ "$ESTABLISHED" -gt 500 ]; then
    echo "  ⚠️  警告: 活跃连接数过多"
fi
echo ""

# 6. 检查是否有 Runner 应用
echo "[6] 检查 Runner 应用..."
CONFIG_FILE="/opt/sslcat/data/sslcat.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="/etc/sslcat/sslcat.conf"
fi
if [ -f "$CONFIG_FILE" ]; then
    RUNNER_COUNT=$(grep -o '"enabled".*true' "$CONFIG_FILE" 2>/dev/null | wc -l || echo "0")
    echo "  启用的 Runner 应用数: $RUNNER_COUNT"
    if [ "$RUNNER_COUNT" -gt 10 ]; then
        echo "  ⚠️  提示: Runner 应用较多，每个应用都有日志检查 goroutine"
    fi
fi
echo ""

# 7. 检查健康检查配置
echo "[7] 检查健康检查配置..."
if [ -f "$CONFIG_FILE" ]; then
    HEALTH_CHECK_COUNT=$(grep -c "health_check_enabled.*true" "$CONFIG_FILE" 2>/dev/null || echo "0")
    HEALTH_CHECK_INTERVAL=$(grep -o '"health_check_interval".*[0-9]' "$CONFIG_FILE" 2>/dev/null | grep -o '[0-9]*' | head -1 || echo "")
    echo "  启用健康检查的规则数: $HEALTH_CHECK_COUNT"
    if [ -n "$HEALTH_CHECK_INTERVAL" ]; then
        echo "  健康检查间隔: ${HEALTH_CHECK_INTERVAL}秒"
        if [ "$HEALTH_CHECK_INTERVAL" -lt 60 ]; then
            echo "  ⚠️  警告: 健康检查间隔过短（建议 ≥ 60 秒）"
        fi
    fi
fi
echo ""

# 8. 生成 CPU Profile（如果 CPU 高）
if [ $(echo "$AVG_CPU > 5" | bc) -eq 1 ]; then
    echo "[8] CPU 使用率较高，生成 CPU Profile（30秒）..."
    echo "  正在收集 CPU Profile，请等待 30 秒..."
    curl -s "http://localhost/debug/pprof/profile?seconds=30" > /tmp/cpu-longrun.prof 2>/dev/null || echo "  ⚠️  无法收集 CPU Profile（可能需要认证）"
    if [ -f /tmp/cpu-longrun.prof ]; then
        FILE_SIZE=$(ls -lh /tmp/cpu-longrun.prof | awk '{print $5}')
        echo "  ✓ CPU Profile 已保存: /tmp/cpu-longrun.prof ($FILE_SIZE)"
        echo "  使用以下命令分析:"
        echo "    go tool pprof -top /tmp/cpu-longrun.prof"
    fi
    echo ""
fi

# 9. 建议
echo "=========================================="
echo "诊断建议"
echo "=========================================="
echo ""

if [ "$GOROUTINE_COUNT" -gt 500 ]; then
    echo "🔴 发现 Goroutine 泄露风险："
    echo "   - 检查是否有未关闭的 goroutine"
    echo "   - 检查 WebSocket 连接是否正确关闭"
    echo "   - 检查日志流是否正确停止"
    echo ""
fi

if [ "$FD_COUNT" -gt 1000 ]; then
    echo "🔴 发现文件描述符泄露风险："
    echo "   - 检查 HTTP 连接是否正确关闭"
    echo "   - 检查是否有未关闭的文件句柄"
    echo ""
fi

if [ $(echo "$AVG_CPU > 10" | bc) -eq 1 ]; then
    echo "🟡 CPU 使用率较高："
    echo "   - 运行 CPU Profile 分析找出热点函数"
    echo "   - 检查是否有忙等待循环"
    echo "   - 检查 GC 频率是否过高"
    echo ""
fi

echo "📊 持续监控命令："
echo "   watch -n 5 'ps -p $PID -o %cpu,%mem,etime && echo \"---\" && ls /proc/$PID/fd 2>/dev/null | wc -l'"
echo ""

