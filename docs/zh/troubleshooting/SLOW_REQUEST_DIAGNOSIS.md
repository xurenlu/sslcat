# 慢请求排查指南

当出现 `/api/monitoring/metrics` 或 `/assets/*.js` 等接口耗时 5–10 秒时，可按以下步骤排查。

## 一、快速诊断

在服务器上执行：

```bash
# 本地执行后 scp 到服务器，或直接 ssh 执行
ssh root@sg1.1605ai.com 'bash -s' < scripts/diagnose-slow-requests.sh
```

## 二、可能原因与对应措施

### 1. 监控指标 API 慢（/api/monitoring/metrics）

| 原因 | 表现 | 处理方式 |
|------|------|----------|
| **数据量过大** | 默认查 7 天，约 1 万条 1min 数据，聚合后 ~2000 条 | 前端改为默认 1 天，或使用 `granularity=daily` |
| **SQLite 查询慢** | 数据库 >50MB 或行数 >10 万 | 缩短保留期、加索引、或改用 SQL 聚合 |
| **JSON 序列化/网络** | 响应体大，弱网或客户端接收慢 | 减少返回点数、启用压缩 |
| **CPU 争用** | 2 核机器同时处理压缩、ML 等 | 降低并发或升级配置 |

### 2. 静态 JS 慢（/assets/index-xxx.js）

| 原因 | 表现 | 处理方式 |
|------|------|----------|
| **首次 Brotli 压缩** | 1MB+ JS 实时压缩，2 核 CPU 可能需数秒 | 预压缩或使用 gzip |
| **压缩缓存未命中** | 每次请求都重新压缩 | 确认压缩缓存配置 |
| **客户端网络慢** | 服务器已写完，但客户端接收慢 | 优化 CDN/网络 |

## 三、使用 pprof 精确定位

1. 在配置中启用 pprof：

```json
{
  "server": {
    "enable_pprof": true
  }
}
```

2. 重启 sslcat，在慢请求发生期间抓 CPU profile：

```bash
# 抓 30 秒 CPU profile（在慢请求发生时执行）
curl -o cpu.prof 'http://127.0.0.1/debug/pprof/profile?seconds=30'

# 本地分析
go tool pprof -http=:8080 cpu.prof
```

3. 在火焰图中查看 `handleAPIMonitoringMetrics`、`GetMetrics`、`json.Marshal`、`CompressStream` 等调用占比。

## 四、代码级优化建议

### 4.1 监控 API：限制默认数据量

前端 `Monitoring.tsx` 可改为默认 1 天，减少首次加载数据量：

```tsx
// 默认 timeRange 从 '7days' 改为 'today'
const [timeRange, setTimeRange] = useState<'today' | '7days' | '30days' | '90days'>('today')
```

### 4.2 监控 API：后端 SQL 聚合

在 `metrics_storage.go` 的 `GetMetrics` 中，对 5min/15min/daily 使用 SQL `GROUP BY` 聚合，而不是拉全量 1min 再在内存聚合，可显著减少数据传输和内存占用。

### 4.3 静态资源：预压缩

构建时生成 `.br` 和 `.gz` 文件，服务时优先返回预压缩版本，避免实时压缩。

## 五、临时缓解

1. **监控页**：首次进入时选择「今天」或「1 天」，减少数据量。
2. **刷新间隔**：`loadStats` 每 5 秒刷新，`loadMetrics` 仅在切换时间范围时触发，无需调整。
3. **网络**：若客户端在海外，可考虑 CDN 或就近节点。
