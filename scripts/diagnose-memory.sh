#!/bin/bash
# SSLCat 内存泄漏诊断脚本
# 用法: bash scripts/diagnose-memory.sh [PID]

set -e

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 获取 PID
if [ -z "$1" ]; then
    PID=$(pgrep -f "sslcat" | head -1)
    if [ -z "$PID" ]; then
        echo -e "${RED}错误: 找不到 sslcat 进程${NC}"
        echo "用法: $0 [PID]"
        exit 1
    fi
    echo -e "${BLUE}自动检测到 sslcat 进程: PID=$PID${NC}"
else
    PID=$1
fi

# 检查进程是否存在
if ! ps -p $PID > /dev/null 2>&1; then
    echo -e "${RED}错误: 进程 $PID 不存在${NC}"
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}SSLCat 内存泄漏诊断报告${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}进程信息:${NC}"
echo "  PID: $PID"
echo "  启动时间: $(ps -p $PID -o lstart=)"
echo "  运行时长: $(ps -p $PID -o etime=)"
echo ""

# 1. 内存使用情况
echo -e "${BLUE}1. 内存使用情况:${NC}"
if command -v ps &> /dev/null; then
    MEM_KB=$(ps -p $PID -o rss= | tr -d ' ')
    MEM_MB=$((MEM_KB / 1024))
    echo "  RSS 内存: ${MEM_MB}MB (${MEM_KB}KB)"
    
    # 警告阈值
    if [ $MEM_MB -gt 1000 ]; then
        echo -e "  ${RED}⚠️  内存使用超过 1GB，可能存在泄漏${NC}"
    elif [ $MEM_MB -gt 500 ]; then
        echo -e "  ${YELLOW}⚠️  内存使用较高 (>500MB)${NC}"
    else
        echo -e "  ${GREEN}✓ 内存使用正常${NC}"
    fi
fi
echo ""

# 2. Goroutine 数量
echo -e "${BLUE}2. Goroutine 数量:${NC}"
if command -v curl &> /dev/null; then
    # 尝试从 pprof 端点获取
    GOROUTINES=$(curl -s http://localhost:6060/debug/pprof/goroutine?debug=1 2>/dev/null | grep "goroutine profile:" | awk '{print $4}')
    
    if [ -n "$GOROUTINES" ]; then
        echo "  Goroutine 总数: $GOROUTINES"
        
        if [ "$GOROUTINES" -gt 10000 ]; then
            echo -e "  ${RED}⚠️  Goroutine 数量异常高 (>10000)${NC}"
        elif [ "$GOROUTINES" -gt 5000 ]; then
            echo -e "  ${YELLOW}⚠️  Goroutine 数量较高 (>5000)${NC}"
        else
            echo -e "  ${GREEN}✓ Goroutine 数量正常${NC}"
        fi
        
        # 显示 top 10 goroutine 类型
        echo ""
        echo "  Top 10 Goroutine 类型:"
        curl -s http://localhost:6060/debug/pprof/goroutine?debug=1 2>/dev/null | \
            grep -E "^[0-9]+ @" | \
            sort -rn | \
            head -10 | \
            awk '{print "    " $1 " 个 goroutines"}'
    else
        echo -e "  ${YELLOW}无法获取 Goroutine 信息 (pprof 端点未启用?)${NC}"
    fi
else
    echo -e "  ${YELLOW}curl 未安装，跳过 Goroutine 检查${NC}"
fi
echo ""

# 3. 文件描述符
echo -e "${BLUE}3. 文件描述符:${NC}"
if [ -d "/proc/$PID/fd" ]; then
    FD_COUNT=$(ls -1 /proc/$PID/fd 2>/dev/null | wc -l)
    echo "  打开的文件描述符: $FD_COUNT"
    
    if [ $FD_COUNT -gt 10000 ]; then
        echo -e "  ${RED}⚠️  文件描述符数量异常高 (>10000)${NC}"
    elif [ $FD_COUNT -gt 5000 ]; then
        echo -e "  ${YELLOW}⚠️  文件描述符数量较高 (>5000)${NC}"
    else
        echo -e "  ${GREEN}✓ 文件描述符数量正常${NC}"
    fi
    
    # 显示文件描述符类型分布
    echo ""
    echo "  文件描述符类型分布:"
    ls -l /proc/$PID/fd 2>/dev/null | \
        awk '{print $NF}' | \
        grep -E "(socket|pipe|anon_inode)" | \
        sort | uniq -c | sort -rn | head -5 | \
        awk '{print "    " $1 " 个 " $2}'
else
    echo -e "  ${YELLOW}/proc 文件系统不可用，跳过文件描述符检查${NC}"
fi
echo ""

# 4. 线程数量
echo -e "${BLUE}4. 线程数量:${NC}"
if [ -d "/proc/$PID/task" ]; then
    THREAD_COUNT=$(ls -1 /proc/$PID/task 2>/dev/null | wc -l)
    echo "  线程总数: $THREAD_COUNT"
    
    if [ $THREAD_COUNT -gt 1000 ]; then
        echo -e "  ${RED}⚠️  线程数量异常高 (>1000)${NC}"
    elif [ $THREAD_COUNT -gt 500 ]; then
        echo -e "  ${YELLOW}⚠️  线程数量较高 (>500)${NC}"
    else
        echo -e "  ${GREEN}✓ 线程数量正常${NC}"
    fi
else
    THREAD_COUNT=$(ps -p $PID -o nlwp= 2>/dev/null | tr -d ' ')
    if [ -n "$THREAD_COUNT" ]; then
        echo "  线程总数: $THREAD_COUNT"
    else
        echo -e "  ${YELLOW}无法获取线程信息${NC}"
    fi
fi
echo ""

# 5. 内存分配统计 (如果 pprof 可用)
echo -e "${BLUE}5. 内存分配统计:${NC}"
if command -v curl &> /dev/null; then
    HEAP_STATS=$(curl -s http://localhost:6060/debug/pprof/heap 2>/dev/null)
    
    if [ -n "$HEAP_STATS" ]; then
        echo "  ✓ 堆内存 profile 可用"
        echo "  提示: 运行以下命令查看详细信息:"
        echo "    go tool pprof http://localhost:6060/debug/pprof/heap"
    else
        echo -e "  ${YELLOW}堆内存 profile 不可用${NC}"
    fi
else
    echo -e "  ${YELLOW}curl 未安装，跳过内存分配检查${NC}"
fi
echo ""

# 6. 日志文件大小
echo -e "${BLUE}6. 日志文件大小:${NC}"
LOG_DIRS=("./data" "./logs" "/var/log/sslcat")
for LOG_DIR in "${LOG_DIRS[@]}"; do
    if [ -d "$LOG_DIR" ]; then
        LOG_SIZE=$(du -sh "$LOG_DIR" 2>/dev/null | awk '{print $1}')
        if [ -n "$LOG_SIZE" ]; then
            echo "  $LOG_DIR: $LOG_SIZE"
        fi
    fi
done
echo ""

# 7. 缓存目录大小
echo -e "${BLUE}7. 缓存目录大小:${NC}"
CACHE_DIRS=("./data/cache" "./data/acme-cache" "./data/upstream-cache")
for CACHE_DIR in "${CACHE_DIRS[@]}"; do
    if [ -d "$CACHE_DIR" ]; then
        CACHE_SIZE=$(du -sh "$CACHE_DIR" 2>/dev/null | awk '{print $1}')
        FILE_COUNT=$(find "$CACHE_DIR" -type f 2>/dev/null | wc -l)
        if [ -n "$CACHE_SIZE" ]; then
            echo "  $CACHE_DIR: $CACHE_SIZE ($FILE_COUNT 个文件)"
        fi
    fi
done
echo ""

# 8. 生成内存快照 (可选)
echo -e "${BLUE}8. 内存快照:${NC}"
read -p "是否生成内存快照用于分析? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    SNAPSHOT_DIR="./memory-snapshots"
    mkdir -p "$SNAPSHOT_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    echo "  正在生成内存快照..."
    
    # Heap profile
    if curl -s http://localhost:6060/debug/pprof/heap > "$SNAPSHOT_DIR/heap_${TIMESTAMP}.prof" 2>/dev/null; then
        echo -e "  ${GREEN}✓ 堆内存快照已保存: $SNAPSHOT_DIR/heap_${TIMESTAMP}.prof${NC}"
    fi
    
    # Goroutine profile
    if curl -s http://localhost:6060/debug/pprof/goroutine > "$SNAPSHOT_DIR/goroutine_${TIMESTAMP}.prof" 2>/dev/null; then
        echo -e "  ${GREEN}✓ Goroutine 快照已保存: $SNAPSHOT_DIR/goroutine_${TIMESTAMP}.prof${NC}"
    fi
    
    # Allocs profile
    if curl -s http://localhost:6060/debug/pprof/allocs > "$SNAPSHOT_DIR/allocs_${TIMESTAMP}.prof" 2>/dev/null; then
        echo -e "  ${GREEN}✓ 内存分配快照已保存: $SNAPSHOT_DIR/allocs_${TIMESTAMP}.prof${NC}"
    fi
    
    echo ""
    echo "  分析快照:"
    echo "    go tool pprof $SNAPSHOT_DIR/heap_${TIMESTAMP}.prof"
    echo "    go tool pprof $SNAPSHOT_DIR/goroutine_${TIMESTAMP}.prof"
fi
echo ""

# 9. 诊断建议
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}诊断建议:${NC}"
echo -e "${GREEN}========================================${NC}"

# 基于检查结果给出建议
if [ -n "$GOROUTINES" ] && [ "$GOROUTINES" -gt 5000 ]; then
    echo -e "${YELLOW}• Goroutine 数量过高，可能存在 goroutine 泄漏${NC}"
    echo "  建议: 检查 WebSocket 连接管理和缓存清理器"
fi

if [ -n "$MEM_MB" ] && [ $MEM_MB -gt 500 ]; then
    echo -e "${YELLOW}• 内存使用较高，建议进一步分析${NC}"
    echo "  建议: 使用 pprof 分析堆内存分配"
    echo "    go tool pprof http://localhost:6060/debug/pprof/heap"
fi

if [ -n "$FD_COUNT" ] && [ $FD_COUNT -gt 5000 ]; then
    echo -e "${YELLOW}• 文件描述符数量过高${NC}"
    echo "  建议: 检查是否有未关闭的连接或文件"
fi

echo ""
echo -e "${BLUE}持续监控命令:${NC}"
echo "  watch -n 5 'ps -p $PID -o pid,rss,vsz,pcpu,pmem,etime,cmd'"
echo ""
echo -e "${BLUE}实时 Goroutine 监控:${NC}"
echo "  watch -n 5 'curl -s http://localhost:6060/debug/pprof/goroutine?debug=1 | grep \"goroutine profile:\"'"
echo ""

echo -e "${GREEN}诊断完成!${NC}"

