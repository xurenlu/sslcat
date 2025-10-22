#!/bin/bash
# SSLcat CPU 性能排查工具
# 用于诊断线上 CPU 占用问题

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  SSLcat CPU 性能排查工具${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# 检查是否以 root 运行
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}警告: 建议以 root 用户运行以获取完整信息${NC}"
fi

# 配置
ADMIN_PREFIX="${ADMIN_PREFIX:-/sslcat-panel}"
API_BASE="${API_BASE:-http://localhost${ADMIN_PREFIX}}"
OUTPUT_DIR="${OUTPUT_DIR:-./cpu-profile-$(date +%Y%m%d-%H%M%S)}"
PROFILE_DURATION="${PROFILE_DURATION:-30}"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}✓${NC} 输出目录: $OUTPUT_DIR"
echo ""

# 1. 获取进程信息
echo -e "${BLUE}[1/8] 获取进程信息...${NC}"
PID=$(pgrep -x sslcat || pgrep -x sslcat-test || echo "")
if [ -z "$PID" ]; then
    echo -e "${RED}✗${NC} 未找到 sslcat 进程"
    exit 1
fi
echo -e "${GREEN}✓${NC} 进程 PID: $PID"

# 保存进程信息
ps -p "$PID" -o pid,ppid,user,%cpu,%mem,vsz,rss,stat,start,time,command > "$OUTPUT_DIR/process_info.txt"
echo "  保存到: $OUTPUT_DIR/process_info.txt"
echo ""

# 2. 获取 CPU 使用率快照
echo -e "${BLUE}[2/8] 获取 CPU 使用率快照...${NC}"
top -b -n 3 -d 1 -p "$PID" > "$OUTPUT_DIR/cpu_snapshot.txt" 2>&1 || \
    echo "top 命令失败，尝试使用 ps..." && \
    for i in {1..3}; do
        ps -p "$PID" -o %cpu,%mem,time,etime,nlwp,stat,command
        sleep 1
    done > "$OUTPUT_DIR/cpu_snapshot.txt"
echo -e "${GREEN}✓${NC} 保存到: $OUTPUT_DIR/cpu_snapshot.txt"

# 计算平均 CPU
AVG_CPU=$(ps -p "$PID" -o %cpu | tail -n 1 | tr -d ' ')
echo -e "  当前 CPU 使用率: ${YELLOW}${AVG_CPU}%${NC}"
echo ""

# 3. 获取 Goroutine 信息
echo -e "${BLUE}[3/8] 获取 Goroutine 信息...${NC}"
if curl -s -f "$API_BASE/api/debug/pprof/goroutine?debug=2" > "$OUTPUT_DIR/goroutines_full.txt" 2>/dev/null; then
    GOROUTINE_COUNT=$(grep -c "^goroutine " "$OUTPUT_DIR/goroutines_full.txt" || echo "0")
    echo -e "${GREEN}✓${NC} Goroutine 数量: ${YELLOW}${GOROUTINE_COUNT}${NC}"
    echo "  保存到: $OUTPUT_DIR/goroutines_full.txt"
    
    # 统计 goroutine 状态
    echo "" > "$OUTPUT_DIR/goroutine_summary.txt"
    echo "=== Goroutine 统计 ===" >> "$OUTPUT_DIR/goroutine_summary.txt"
    echo "总数: $GOROUTINE_COUNT" >> "$OUTPUT_DIR/goroutine_summary.txt"
    echo "" >> "$OUTPUT_DIR/goroutine_summary.txt"
    echo "按函数统计:" >> "$OUTPUT_DIR/goroutine_summary.txt"
    grep "^goroutine " "$OUTPUT_DIR/goroutines_full.txt" | \
        sed 's/goroutine [0-9]* \[//' | sed 's/\]:.*//' | \
        sort | uniq -c | sort -rn >> "$OUTPUT_DIR/goroutine_summary.txt"
    
    echo "  统计信息: $OUTPUT_DIR/goroutine_summary.txt"
else
    echo -e "${RED}✗${NC} 无法访问 pprof 端点 ($API_BASE/api/debug/pprof)"
    echo "  请确保 pprof 已启用且管理面板可访问"
fi
echo ""

# 4. 收集 CPU Profile
echo -e "${BLUE}[4/8] 收集 CPU Profile (${PROFILE_DURATION}秒)...${NC}"
echo "  这可能需要一些时间，请耐心等待..."
if curl -s -f "$API_BASE/api/debug/pprof/profile?seconds=$PROFILE_DURATION" > "$OUTPUT_DIR/cpu.prof" 2>/dev/null; then
    FILE_SIZE=$(ls -lh "$OUTPUT_DIR/cpu.prof" | awk '{print $5}')
    echo -e "${GREEN}✓${NC} CPU Profile 已保存: $OUTPUT_DIR/cpu.prof ($FILE_SIZE)"
    
    # 分析 CPU profile
    if command -v go &> /dev/null; then
        echo "  分析 CPU Profile..."
        go tool pprof -top "$OUTPUT_DIR/cpu.prof" > "$OUTPUT_DIR/cpu_top.txt" 2>&1 || true
        go tool pprof -list="watchLogs|WatchDeployTriggers|checkAllBackends" "$OUTPUT_DIR/cpu.prof" > "$OUTPUT_DIR/cpu_hotspots.txt" 2>&1 || true
        echo "  分析结果: $OUTPUT_DIR/cpu_top.txt"
    fi
else
    echo -e "${RED}✗${NC} 无法收集 CPU Profile"
fi
echo ""

# 5. 获取内存信息
echo -e "${BLUE}[5/8] 获取内存信息...${NC}"
if curl -s -f "$API_BASE/api/debug/pprof/heap" > "$OUTPUT_DIR/heap.prof" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Heap Profile 已保存: $OUTPUT_DIR/heap.prof"
    
    if command -v go &> /dev/null; then
        go tool pprof -top "$OUTPUT_DIR/heap.prof" > "$OUTPUT_DIR/heap_top.txt" 2>&1 || true
    fi
else
    echo -e "${RED}✗${NC} 无法收集 Heap Profile"
fi
echo ""

# 6. 检查配置文件
echo -e "${BLUE}[6/8] 检查配置文件...${NC}"
CONFIG_FILES=(
    "/etc/sslcat/sslcat.conf"
    "/usr/local/etc/sslcat/sslcat.conf"
    "$(pwd)/sslcat.conf"
    "$(pwd)/data/sslcat.conf"
)

for config in "${CONFIG_FILES[@]}"; do
    if [ -f "$config" ]; then
        echo -e "${GREEN}✓${NC} 找到配置文件: $config"
        cp "$config" "$OUTPUT_DIR/sslcat.conf"
        
        # 统计配置信息
        echo "" > "$OUTPUT_DIR/config_summary.txt"
        echo "=== 配置摘要 ===" >> "$OUTPUT_DIR/config_summary.txt"
        
        # 统计 Runner 应用数量
        RUNNER_COUNT=$(grep -c '"enabled".*true' "$config" 2>/dev/null | grep -c runner || echo "0")
        echo "Runner 应用数量: $RUNNER_COUNT" >> "$OUTPUT_DIR/config_summary.txt"
        
        # 统计代理规则数量
        PROXY_COUNT=$(grep -c '"proxy_rules"' "$config" 2>/dev/null || echo "0")
        echo "代理规则数量: $PROXY_COUNT" >> "$OUTPUT_DIR/config_summary.txt"
        
        # 统计静态站点数量
        STATIC_COUNT=$(grep -c '"static_sites"' "$config" 2>/dev/null || echo "0")
        echo "静态站点数量: $STATIC_COUNT" >> "$OUTPUT_DIR/config_summary.txt"
        
        break
    fi
done
echo ""

# 7. 检查已知问题
echo -e "${BLUE}[7/8] 检查已知 CPU 问题...${NC}"
echo "" > "$OUTPUT_DIR/known_issues_check.txt"
echo "=== 已知问题检查 ===" >> "$OUTPUT_DIR/known_issues_check.txt"
echo "" >> "$OUTPUT_DIR/known_issues_check.txt"

# 检查是否有忙等待的 goroutine
if [ -f "$OUTPUT_DIR/goroutines_full.txt" ]; then
    BUSY_WAIT=$(grep -c "watchLogs\|WatchDeployTriggers" "$OUTPUT_DIR/goroutines_full.txt" || echo "0")
    echo "1. 日志监听和部署监听 Goroutine: $BUSY_WAIT" >> "$OUTPUT_DIR/known_issues_check.txt"
    if [ "$BUSY_WAIT" -gt 20 ]; then
        echo -e "${YELLOW}⚠${NC} 警告: 发现大量日志/部署监听 goroutine ($BUSY_WAIT 个)"
        echo "   → 可能是 Runner 应用过多导致" >> "$OUTPUT_DIR/known_issues_check.txt"
    fi
fi

# 检查健康检查
if [ -f "$OUTPUT_DIR/goroutines_full.txt" ]; then
    HEALTH_CHECK=$(grep -c "checkBackendHealth\|HealthChecker" "$OUTPUT_DIR/goroutines_full.txt" || echo "0")
    echo "2. 健康检查 Goroutine: $HEALTH_CHECK" >> "$OUTPUT_DIR/known_issues_check.txt"
    if [ "$HEALTH_CHECK" -gt 50 ]; then
        echo -e "${YELLOW}⚠${NC} 警告: 发现大量健康检查 goroutine ($HEALTH_CHECK 个)"
        echo "   → 可能是负载均衡规则过多或并发控制失效" >> "$OUTPUT_DIR/known_issues_check.txt"
    fi
fi

echo -e "${GREEN}✓${NC} 检查完成: $OUTPUT_DIR/known_issues_check.txt"
cat "$OUTPUT_DIR/known_issues_check.txt"
echo ""

# 8. 生成报告
echo -e "${BLUE}[8/8] 生成诊断报告...${NC}"
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# SSLcat CPU 性能诊断报告

## 📊 概览

本目录包含 SSLcat CPU 性能诊断的所有数据。

## 📁 文件说明

### 基本信息
- `process_info.txt` - 进程基本信息
- `cpu_snapshot.txt` - CPU 使用率快照
- `sslcat.conf` - 当前配置文件
- `config_summary.txt` - 配置摘要

### Goroutine 分析
- `goroutines_full.txt` - 所有 goroutine 的完整堆栈
- `goroutine_summary.txt` - Goroutine 统计摘要

### 性能分析
- `cpu.prof` - CPU Profile 数据（可用 go tool pprof 分析）
- `cpu_top.txt` - CPU 占用最高的函数
- `cpu_hotspots.txt` - 已知热点函数分析
- `heap.prof` - 内存 Profile 数据
- `heap_top.txt` - 内存占用最高的函数

### 问题检查
- `known_issues_check.txt` - 已知问题检查结果

## 🔍 分析步骤

### 1. 查看 CPU 使用率
```bash
cat cpu_snapshot.txt
```

### 2. 检查 Goroutine 数量
```bash
cat goroutine_summary.txt
```

如果 Goroutine 数量异常高（> 1000），说明可能存在 goroutine 泄露。

### 3. 分析 CPU Profile
```bash
go tool pprof -top cpu.prof
```

查看 CPU 占用最高的函数。正常情况下，不应该有函数持续占用大量 CPU。

### 4. 查找热点函数
```bash
go tool pprof -list="函数名" cpu.prof
```

### 5. 检查已知问题
```bash
cat known_issues_check.txt
```

## 🚨 常见问题

### 问题 1: Goroutine 数量过多
**症状**: goroutine_summary.txt 显示数千个 goroutine

**原因**: 
- Runner 应用过多
- Goroutine 泄露
- 健康检查过于频繁

**解决方案**:
- 减少 Runner 应用数量
- 增加健康检查间隔
- 检查代码是否存在 goroutine 泄露

### 问题 2: watchLogs 或 WatchDeployTriggers 占用高
**症状**: cpu_top.txt 显示这些函数占用 CPU 高

**原因**: 忙等待循环（select default 分支）

**解决方案**: 
- 升级到最新版本（已修复）
- 或手动应用 CPU_FIX_PATCH.md 中的补丁

### 问题 3: 健康检查占用高
**症状**: cpu_top.txt 显示 checkBackendHealth 占用高

**原因**: 
- 负载均衡规则过多
- 健康检查间隔过短
- 并发控制失效

**解决方案**:
- 增加健康检查间隔（建议 ≥ 60 秒）
- 减少后端服务器数量
- 升级到包含并发控制的版本

### 问题 4: HTTP 请求处理占用高
**症状**: cpu_top.txt 显示 ServeHTTP 或相关函数占用高

**原因**: 真实的业务负载

**解决方案**: 这是正常的，考虑：
- 增加服务器资源
- 优化应用代码
- 使用缓存
- 负载均衡到多台服务器

## 📞 获取帮助

如果无法自行解决问题，请将此目录打包发送给开发者：

```bash
cd ..
tar czf cpu-profile.tar.gz cpu-profile-*/
```

邮件发送到: m@some.im
或提交 GitHub Issue: https://github.com/xurenlu/sslcat/issues
EOF

echo -e "${GREEN}✓${NC} 报告已生成: $OUTPUT_DIR/README.md"
echo ""

# 总结
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  诊断完成${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo -e "📊 诊断摘要:"
echo -e "  - 进程 PID: ${GREEN}$PID${NC}"
echo -e "  - CPU 使用率: ${YELLOW}${AVG_CPU}%${NC}"
[ -n "$GOROUTINE_COUNT" ] && echo -e "  - Goroutine 数量: ${YELLOW}${GOROUTINE_COUNT}${NC}"
echo ""
echo -e "📁 所有数据已保存到: ${GREEN}$OUTPUT_DIR${NC}"
echo ""
echo -e "🔍 下一步:"
echo -e "  1. 查看概览: ${BLUE}cat $OUTPUT_DIR/known_issues_check.txt${NC}"
echo -e "  2. 分析 CPU: ${BLUE}go tool pprof -top $OUTPUT_DIR/cpu.prof${NC}"
echo -e "  3. 查看 Goroutine: ${BLUE}cat $OUTPUT_DIR/goroutine_summary.txt${NC}"
echo -e "  4. 阅读完整报告: ${BLUE}cat $OUTPUT_DIR/README.md${NC}"
echo ""

# CPU 警告
if [ -n "$AVG_CPU" ]; then
    CPU_INT=$(echo "$AVG_CPU" | cut -d. -f1)
    if [ "$CPU_INT" -gt 80 ]; then
        echo -e "${RED}⚠ 警告: CPU 使用率过高 (${AVG_CPU}%)${NC}"
        echo -e "${YELLOW}建议立即检查:${NC}"
        echo -e "  - $OUTPUT_DIR/cpu_top.txt"
        echo -e "  - $OUTPUT_DIR/known_issues_check.txt"
        echo ""
    fi
fi

# Goroutine 警告
if [ -n "$GOROUTINE_COUNT" ] && [ "$GOROUTINE_COUNT" -gt 500 ]; then
    echo -e "${YELLOW}⚠ 提示: Goroutine 数量较多 (${GOROUTINE_COUNT})${NC}"
    echo -e "  建议检查是否存在 goroutine 泄露"
    echo ""
fi

echo -e "${GREEN}完成！${NC}"

