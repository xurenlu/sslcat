# SSLcat 高并发代码 Review

日期：2026-06-21  
版本：2.3.0-rc1

## 结论

本轮重点审查代理请求路径、配置热重载、日志、统计采集、MCP 和长连接模块。MCP 可观测性已增强，能通过 MCP 查看近期内部错误和所有站点 error log；同时修复了一个统计采样路径的 map data race。

仍建议把“运行时配置快照/热重载并发读写”作为下一轮 P1 专项处理。当前代码里请求路径、proxy manager、MCP 和热重载共享 `*config.Config`，缺少统一读写边界，在高并发请求叠加配置热更新时有数据竞争风险。

## 已修复

### 1. 统计采样无锁读取 map 长度

- 文件：`internal/statistics/collector.go`
- 问题：`shouldSampleForFunnel` 读取 `len(c.ipEntries)` 时原先未加锁，而请求记录路径会在同一个 map 上写入。
- 风险：高并发统计更新时可能被 `go test -race` 抓出 data race，极端情况下触发运行时 map 并发读写异常。
- 处理：已加 `RLock/RUnlock` 保护读取。

## 新增 MCP 可观测性

### 1. MCP tools

- `error_log_list`：列出内部错误日志和所有 proxy/static/php 站点 error log 来源。
- `error_log_tail`：按 `id`、`kind`、`domain`、`keyword`、`since`、`limit` 读取近期错误。

### 2. MCP resources

- `sslcat://logs/error-sources`
- `sslcat://logs/error{?id,kind,domain,since,keyword,limit,max_bytes}`

### 3. 高并发保护

- 新增 `internal/mcp/logview`，默认只读日志尾部 1MB，最大 4MB。
- `limit` 默认 200，最大 2000。
- 避免 MCP 排障时对大日志文件做全量读取。

## 仍需关注的高并发风险

### P1. 配置热重载与请求路径共享 `*config.Config`

- 证据：
  - `internal/web/server_setup.go:168-173` 直接替换 `s.config`。
  - `internal/web/server_setup.go:436-449` 原地覆盖 `s.config` 多个大字段。
  - `internal/proxy/manager.go:1012-1013` 请求侧通过 `m.config.GetProxyRule` 读取规则。
  - `internal/proxy/manager.go:2438-2444` reload 时直接替换 `m.config`。
- 风险：请求路径正在遍历 proxy/static/php 配置时，热重载或管理 API 同步修改 slice/map，可能出现 data race 或读到半更新状态。
- 建议：引入运行时配置快照层，例如 `atomic.Value` 保存不可变 `*ConfigSnapshot`；所有请求只读快照，配置保存/热重载构造新快照后原子替换。短期可先给 `Server` 和 `proxy.Manager` 增加统一 `configMu`，但长期更推荐不可变快照。

### P2. 错误日志仍是同步写入

- 证据：`internal/logger/error_log.go:220-256` 在请求相关路径里持 mutex 格式化并直接 `Fprintln` 写文件。
- 风险：错误风暴时所有错误日志写入串行等待磁盘，可能反压请求或 PHP 错误处理路径。
- 建议：复用访问日志的异步队列设计，增加 drop/backpressure 统计；MCP 已能读取 error log 后，建议同时暴露 dropped/error queue 指标。

### P2. ReverseProxy 缓存创建存在重复构造窗口

- 证据：`internal/proxy/manager.go:1328-1341` 先读缓存，未命中后释放锁创建 proxy。
- 风险：同一新规则首次高并发命中时可能重复创建多个 `ReverseProxy` 和 transport 相关对象，虽然最终缓存写入会收敛，但会造成瞬时额外分配。
- 建议：对 proxy cache miss 使用 double-check 写锁，或 `singleflight.Group` 合并同 key 初始化。

### P3. 访问日志异步队列已有保护，但需要运维告警

- 证据：`internal/logger/access.go:243-247` 队列满时丢弃并累加 `droppedLogs`，`internal/logger/access.go:424-443` stats 暴露 dropped/queue 信息。
- 风险：高峰时日志丢弃是正确降级，但如果没有告警，排障时会误以为没有流量或没有异常。
- 建议：把 dropped log 指标纳入 Prometheus/监控页面，并在 MCP metrics snapshot 中补充访问日志丢弃数。

## 验证

- `go test ./internal/mcp/... ./internal/statistics ./cmd/mcp-testserver`
- `go test ./internal/web -run 'Test.*MCP|TestReadRecentJSONLinesReturnsTailOnly|TestReadTailLinesHonorsMaxBytes|TestVersion'`
- `ruby tests/mcp_e2e.rb`

Ruby E2E 报告：

- `reports/mcp_e2e.json`
- `reports/mcp_e2e.md`
