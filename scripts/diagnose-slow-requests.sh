#!/bin/bash
# SSLcat 慢请求排查脚本
# 用法: 在 sg1.1605ai.com 上运行，或通过 ssh root@sg1.1605ai.com 'bash -s' < scripts/diagnose-slow-requests.sh

set -e

echo "=========================================="
echo "  SSLcat 慢请求诊断"
echo "=========================================="
echo ""

# 1. 数据库与数据量
echo "【1】指标数据库"
DB_PATH="/opt/sslcat/data/process_metrics.db"
if [ -f "$DB_PATH" ]; then
  echo "  路径: $DB_PATH"
  ls -la "$DB_PATH"
  if command -v python3 &>/dev/null; then
    python3 << PYEOF
import sqlite3
import os
db = "$DB_PATH"
if os.path.exists(db):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT count(*) FROM process_metrics")
    total = c.fetchone()[0]
    print(f"  总行数: {total}")
    c.execute("SELECT granularity, count(*) FROM process_metrics GROUP BY granularity")
    for r in c.fetchall():
        print(f"    - {r[0]}: {r[1]} 条")
    # 7天 1min 约 10080 条，5min 聚合后约 2016 条
    print(f"  7天默认查询约返回: {min(total, 10080)} 条原始 -> 聚合后 ~2016 条")
    conn.close()
PYEOF
  fi
else
  echo "  未找到数据库"
fi
echo ""

# 2. SQL 查询耗时
echo "【2】SQLite 查询耗时测试"
if [ -f "$DB_PATH" ] && command -v python3 &>/dev/null; then
  python3 << 'PYEOF'
import sqlite3
import time
db = "/opt/sslcat/data/process_metrics.db"
conn = sqlite3.connect(db)
c = conn.cursor()
c.execute("SELECT min(timestamp), max(timestamp) FROM process_metrics")
min_ts, max_ts = c.fetchone()
# 模拟 7 天查询
start = time.perf_counter()
c.execute("""
    SELECT id, timestamp, granularity, cpu_percent, memory_mb, memory_percent, sample_count, created_at
    FROM process_metrics WHERE timestamp >= ? AND timestamp <= ? AND granularity = ?
    ORDER BY timestamp ASC
""", (min_ts, max_ts, "1min"))
rows = c.fetchall()
elapsed = time.perf_counter() - start
print(f"  查询 {len(rows)} 条 1min 数据: {elapsed:.3f}s")
conn.close()
PYEOF
fi
echo ""

# 3. 服务器资源
echo "【3】服务器资源"
echo "  CPU 核心: $(nproc 2>/dev/null || echo '?')"
free -h 2>/dev/null | head -2 || true
uptime
echo ""

# 4. 本地请求耗时（需有效 token 时才有意义）
echo "【4】本地 API 耗时（无 token 会 401，仅看延迟）"
curl -s -o /dev/null -w "  metrics API: %{http_code}, %{time_total}s\n" \
  "http://127.0.0.1/sslcat-panel/api/monitoring/metrics?start_time=2025-01-01T00:00:00Z&end_time=2025-01-02T00:00:00Z&granularity=daily" \
  -H "Cookie: sslcat_token=invalid" 2>/dev/null || true

# 5. 静态资源
echo ""
echo "【5】静态资源（无压缩）"
JS_PATH=$(curl -s "http://127.0.0.1/sslcat-panel/" 2>/dev/null | grep -oE 'src="[^"]+index-[^"]+\.js"' | head -1 | sed 's/src="//;s/"//')
if [ -n "$JS_PATH" ]; then
  FULL_URL="http://127.0.0.1${JS_PATH}"
  curl -s -o /dev/null -w "  %{url_effective}: %{http_code}, %{time_total}s, %{size_download} bytes\n" \
    "$FULL_URL" -H "Accept-Encoding: identity" 2>/dev/null || true
fi

echo ""
echo "【6】pprof 状态"
if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:6060/debug/pprof/" 2>/dev/null | grep -q 200; then
  echo "  pprof 已启用: http://127.0.0.1:6060/debug/pprof/"
  echo "  抓 CPU 30s: curl -o cpu.prof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'"
else
  echo "  pprof 未启用，在配置中设置 server.enable_pprof: true、server.pprof_addr: 127.0.0.1:6060 后重启"
fi

echo ""
echo "=========================================="
echo "  排查建议见: docs/zh/troubleshooting/SLOW_REQUEST_DIAGNOSIS.md"
echo "=========================================="
