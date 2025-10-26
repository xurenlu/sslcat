# 定时器质数间隔优化方案

## 优化原则

将不会影响用户通知的后台清理任务改为质数间隔，避免多个定时器同时触发。

## 修改列表

### ✅ 可以改成质数的定时器（后台清理任务）

| 原间隔 | 新间隔 | 文件 | 原因 |
|--------|--------|------|------|
| 30秒 | 31秒 | internal/monitor/performance_monitor.go | 性能监控，后台任务 |
| 30秒 | 37秒 | internal/runner/realtime_logs.go | 实时日志心跳，后台任务 |
| 30秒 | 29秒 | internal/proxy/manager.go | WebSocket监控，后台任务 |
| 30秒 | 31秒 | internal/web/server.go | LE域名刷新，后台任务 |
| 60秒 | 59秒 | internal/monitor/memory_monitor.go | 内存监控，后台任务 |
| 60秒 | 61秒 | internal/monitor/goroutine_monitor.go | Goroutine监控，后台任务 |
| 60秒 | 53秒 | internal/cache/cdncache.go | CDN缓存清理，后台任务 |
| 60秒 | 59秒 | internal/health/checker.go | 健康检查，后台任务 |
| 60秒 | 61秒 | internal/loadbalancer/healthcheck.go | 负载均衡健康检查，后台任务 |
| 5分钟 | 7分钟 | internal/cache/memory_cache.go | 内存缓存清理，后台任务 |
| 5分钟 | 11分钟 | internal/security/advanced_rate_limiter.go | 安全限流器清理，后台任务 |
| 5分钟 | 13分钟 | internal/ssl/manager.go | ACME证书同步，后台任务 |
| 5分钟 | 17分钟 | internal/web/proxy_auth.go | 代理认证清理，后台任务 |
| 5分钟 | 19分钟 | internal/web/captcha.go | 验证码清理，后台任务 |
| 10分钟 | 11分钟 | internal/web/session_manager.go | 会话清理，后台任务 |
| 10分钟 | 13分钟 | internal/web/session_storage.go | 会话存储清理，后台任务 |
| 30分钟 | 31分钟 | internal/threatintel/manager.go | 威胁情报更新，后台任务 |
| 1小时 | 59分钟 | internal/threatintel/database.go | 威胁情报清理，后台任务 |
| 1小时 | 61分钟 | internal/cache/upstream_cache.go | 上游缓存清理，后台任务 |

### ❌ 保持原样的定时器（可能影响用户或需要精确时间）

| 间隔 | 文件 | 原因 |
|------|------|------|
| 1秒 | internal/runner/realtime_logs.go | 实时日志检查，需要实时性 |
| 5秒 | internal/web/server.go | 配置文件监听，需要快速响应 |
| 12小时 | internal/ssl/manager.go | 证书到期提醒，需要固定时间 |
| 24小时 | internal/ssl/manager.go | 证书自动续期，需要固定时间 |
| 24小时 | internal/threatintel/manager.go | 威胁情报每天清理，需要固定时间 |
| 3-15秒 | internal/ssl/dns_*.go | SSL DNS验证，任务很短 |

## 预期效果

### 修改前（整点叠加）
```
04:00:00 - 17个任务同时触发 💥
```

### 修改后（分散执行）
```
04:00:00 - 2个任务（证书相关）
04:00:53 - 1个任务（CDN缓存清理）
04:00:59 - 1个任务（内存监控）
04:01:00 - 1个任务（健康检查）
04:01:01 - 1个任务（Goroutine监控）
...
04:07:00 - 1个任务（内存缓存清理）
04:11:00 - 2个任务（安全限流器清理 + 会话清理）
04:13:00 - 2个任务（ACME证书同步 + 会话存储清理）
04:17:00 - 1个任务（代理认证清理）
04:19:00 - 1个任务（验证码清理）
...
04:31:00 - 1个任务（威胁情报更新）
04:59:00 - 1个任务（威胁情报清理）
05:01:00 - 1个任务（上游缓存清理）
```

**最大同时触发任务数：3个**（vs 之前的 17个）

## 实施步骤

1. 修改代码文件
2. 更新文档
3. 测试验证
4. 部署

