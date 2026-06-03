# MCP 内置接入（v2.1.0-rc1+）

sslcat 自 `v2.1.0-rc1` 起内置一个 [Model Context Protocol](https://modelcontextprotocol.io/) 服务端。
把连接信息交给任意支持 MCP 的 AI 客户端（Claude Desktop、Cursor、Cherry Studio 等），
AI 就能直接调用 sslcat 工具来运维。

> 当前状态：**P4（站点 + 证书 + 转发 + 上游健康检查 + Resources + 长任务轮询 + destructive 二次确认 + Prometheus 指标）**。后续 P5 是前端 Token 管理页 + Ruby 端到端测试 + 正式 v2.1.0。

---

## 协议与端点

- 协议：MCP Streamable HTTP（JSON-RPC 2.0 over HTTP，单端点）。
- 端点：`https://<your-host>${admin_prefix}${mcp.path_prefix}/stream`
  - 默认即 `https://<your-host>/sslcat-panel/mcp/stream`。
- 健康检查：`GET https://<your-host>/sslcat-panel/mcp/health` → `{"status":"ok","protocol":"…"}`。
- 鉴权：HTTP 头 `Authorization: Bearer <token>`，token 由 `sslcat mcp token create` 颁发。

---

## 快速开始

### 1. 启用 MCP

```bash
sslcat mcp enable
```

或者直接修改 `sslcat.conf`：

```json
{
  "mcp": {
    "enabled": true,
    "path_prefix": "/mcp",
    "audit": { "enabled": true, "file": "./data/mcp_audit.log" }
  }
}
```

### 2. 颁发一个 token

```bash
sslcat mcp token create \
  --name claude-desktop-rocky \
  --scopes read \
  --rate-limit 60/min \
  --desc "rocky 个人电脑的 Claude Desktop"
```

输出示例：

```
✅ MCP token 创建成功（此 token 仅在本次输出，请立刻保存）：

  Name        : claude-desktop-rocky
  Token       : sslcat_mcp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  Scopes      : read
  Rate Limit  : 60/min

接入示例（Cherry Studio / Cursor / Claude Desktop 等 MCP 客户端）：
  URL    : https://<your-host>/sslcat-panel/mcp/stream
  Header : Authorization: Bearer sslcat_mcp_xxxxxxxx…
```

> ⚠️ 明文 token 只显示一次，丢了只能 revoke 重发。

### 3. 重启 sslcat 主进程

让新的配置生效。

### 4. 自检

```bash
sslcat mcp doctor
```

如果设置了 `SSLCAT_LOCAL_URL=http://127.0.0.1:8080` 环境变量，doctor 还会探测一次健康检查端点。

---

## Scope（权限范围）

| scope | 覆盖工具 | 备注 |
|---|---|---|
| `read` | `version_info`、`site_list`、`cert_list`、`proxy_route_list` | 只读 |
| `site:write` | （P2 起）站点 CRUD | 写 |
| `cert:write` | （P3 起）证书申请/续期/删除 | 写 |
| `proxy:write` | （P4 起）转发路由 CRUD | 写 |
| `security:write` | 后续：WAF / IP 封禁 | 写 |
| `ops:write` | 后续：配置热加载 / 备份 / 部署任务 | 写 |
| `admin` | 全部 | 谨慎使用 |

scope 在 token 上设置；调用 tool 时会在 server 端校验，缺权限直接报 `-32002 forbidden`。

---

## P1 提供的工具

调用方式：标准 MCP `tools/call`，参数详见 `tools/list` 返回的 `inputSchema`。

### `version_info`

无参数。返回 sslcat 版本、构建标识、MCP 协议版本、集群角色与代理统计。

### `site_list`

```json
{ "keyword": "example", "enabled_only": true }
```

返回反向代理站点摘要（域名、后端、SSL 状态、证书是否就绪等）。

### `cert_list`

```json
{ "domain": "example.com", "expiring_within_days": 30 }
```

返回证书列表。`expiring_within_days` 用于挑出即将到期的证书。

### `proxy_route_list`

```json
{ "domain": "api.example.com" }
```

返回反代路由的完整详情（路径前缀规则、健康检查、会话保持、超时…），适合 AI 诊断转发问题。

---

## P2 提供的写类工具（需 scope=site:write）

### `site_add`

```json
{
  "domain": "api.example.com",
  "backend": { "host": "10.0.0.10", "port": 8080 },
  "ssl_only": true,
  "health_check": { "enabled": true, "path": "/healthz", "interval_sec": 30 }
}
```

新增反代站点。`backend` 与 `backends` 二选一。新增成功后会异步预取证书。
若 domain 已存在，返回 `already exists`——改用 `site_update`。

### `site_update`

```json
{
  "domain": "api.example.com",
  "ssl_only": true,
  "backends": [
    { "host": "10.0.0.10", "port": 8080, "weight": 2 },
    { "host": "10.0.0.11", "port": 8080, "weight": 1 }
  ]
}
```

按 domain patch 字段。未传字段不动；传 `backends` 会**整体替换**后端集合。

### `site_enable` / `site_disable`

```json
{ "domain": "api.example.com" }
```

启停站点。如果已是目标状态，返回 `{ "ok": true, "no_op": true }` 不再写盘。
启用时同样会异步预取证书。

### `site_delete`（destructive）

```json
{ "domain": "api.example.com" }
```

**两阶段调用**：
1. 第一次不带 `confirm`，返回：
   ```json
   {
     "requires_confirmation": true,
     "confirm_token": "<64 hex chars>",
     "message": "即将删除站点 ...",
     "preview": { "action": "delete", "site": { ... } }
   }
   ```
   AI 客户端应当把 message 复述给用户，得到确认后再发第二次。
2. 第二次带上 token：
   ```json
   { "domain": "api.example.com", "confirm": "<token from first call>" }
   ```

token 的生存期是 **60 秒**，并绑定 `(token_name, tool, canonicalized_args)`——
跨工具复用、跨参数复用、跨调用方复用都会被拒绝；用过即焚，无法重放。

> ⚠️ `site_delete` **只删反代路由**，不会删除已签发的证书。如需清理证书，
> P3 完工后用 `cert_delete`（同样 destructive、同样需要二次确认）。

---

## P3 提供的证书 + 长任务工具

### `cert_issue`（异步，scope=cert:write）

```json
{
  "domain": "api.example.com",
  "challenge": "http-01"
}
```

或 DNS-01：

```json
{
  "domain": "*.example.com",
  "challenge": "dns-01",
  "dns_provider": "cloudflare-prod"
}
```

立即返回 `task_id`，**不会阻塞**。证书申请通常 10~30 秒，用 `task_status` 轮询：

```json
{
  "ok": true,
  "task_id": "9c8a7b6e-...",
  "status": "pending",
  "poll_with": "task_status",
  "poll_example": { "task_id": "9c8a7b6e-..." }
}
```

通配域名（`*.example.com`）自动强制 dns-01；未配置 `ssl.email` 时直接报错。

### `cert_renew`（异步，scope=cert:write）

参数与 `cert_issue` 相同。会先清空 ACME cache 再申请。

### `cert_upload`（同步，scope=cert:write）

```json
{
  "domain": "api.example.com",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "key_pem":  "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"
}
```

校验顺序：PEM 解析 → cert/key 配对 → CN/SAN 覆盖 domain → 写盘 → reload。任何一步失败都返回 `isError=true`，**不会**写出半成品文件。

### `cert_delete`（destructive，scope=cert:write）

```json
{ "domain": "api.example.com" }
```

两阶段（同 `site_delete`）。第一次预演会额外提示：

- `used_by_site` —— 该域名是否还有反代规则在用；
- `days_remaining` —— 还有多少天到期（避免误删长期有效证书）；
- `self_signed` —— 是否只是自签兜底，删了无所谓。

### `cert_dns_provider_list`（scope=read）

无参数。返回 sslcat 已配置的 DNS 厂商及健康状态。`cert_issue` dns-01 模式之前先调它选 provider。

### `task_status`（scope=read）

```json
{ "task_id": "9c8a7b6e-...", "include_events": true }
```

返回任务详情：

```json
{
  "id": "9c8a7b6e-...",
  "tool": "cert_issue",
  "status": "running",
  "progress": 60,
  "message": "using_http01",
  "events": [
    { "time": "...", "progress": 5,  "status": "started",      "message": "..." },
    { "time": "...", "progress": 30, "status": "checking_dns", "message": "..." },
    { "time": "...", "progress": 60, "status": "using_http01", "message": "..." }
  ],
  "owner_name": "claude-desktop-rocky",
  "created_at": "...",
  "updated_at": "..."
}
```

`status` 取值：`pending / running / succeeded / failed`。AI 客户端循环调用直到 `succeeded` 或 `failed` 即可。

> 🔒 **Owner 隔离**：每个 token 只能查到自己创建的任务。`admin` scope 可查全部。

### `task_list`（scope=read）

```json
{ "status": "running", "limit": 20 }
```

只返回顶层字段（id / tool / status / progress / message / 时间戳 / error），不展开 events——要详情请用 `task_status`。

---

## P4 提供的转发 + 健康检查工具

### `proxy_route_add`（scope=proxy:write）

在已有站点上加一条 PathPrefixRule。先 `site_add` 把站点建好。

```json
{
  "domain": "api.example.com",
  "rule": {
    "name": "v2-api",
    "prefixes": ["/api/v2/"],
    "exact": false,
    "backends": [
      { "host": "10.0.0.10", "port": 8080, "weight": 2 },
      { "host": "10.0.0.11", "port": 8080, "weight": 1 }
    ]
  }
}
```

同站内 `rule.name` 必须唯一，prefix 必须以 `/` 开头。

### `proxy_route_update`（scope=proxy:write）

按 `(domain, name)` 定位并 patch 字段：

```json
{
  "domain": "api.example.com",
  "name": "v2-api",
  "enabled": false,
  "backends": [{ "host": "10.0.0.99", "port": 9090 }]
}
```

传 `backends` 会**整体替换**；未传字段不动。

### `proxy_route_delete`（scope=proxy:write, destructive）

两阶段确认。预演含 prefixes/backends 详情：

```json
{
  "requires_confirmation": true,
  "confirm_token": "...",
  "message": "即将删除站点 \"api.example.com\" 的路由 \"v2-api\"（涉及前缀 [/api/v2/]）。dry-run。",
  "preview": { "action": "delete_route", "domain": "api.example.com", "route": { ... } }
}
```

第二次带 `"confirm": "<token>"` 才真正删。

### `upstream_health_check`（scope=read）

对站点后端并发 TCP 拨号探测：

```json
{ "domain": "api.example.com", "timeout_ms": 1500, "include_routes": true }
```

返回每个后端的可达性与响应时间：

```json
{
  "domain": "api.example.com",
  "timeout_ms": 1500,
  "total": 4,
  "reachable": 3,
  "all_reachable": false,
  "results": [
    { "host": "10.0.0.10", "port": 8080, "reachable": true, "latency_ms": 12 },
    { "host": "10.0.0.11", "port": 8080, "reachable": false, "latency_ms": 1500, "error": "i/o timeout" },
    ...
  ]
}
```

> 仅 TCP 拨号，不走 HTTP 健康检查路径——服务侦听端口但应用挂死的场景检测不出来。

---

## Resources（v2.1.0-rc8+）

Resource 是 MCP 协议提供的"被 AI 拉取的命名上下文"，比 tool 更适合大段只读数据。AI 客户端通过 `resources/list`、`resources/templates/list`、`resources/read` 三个标准方法访问。

### 列出可用 resource

```jsonc
// resources/list 返回静态 URI 列表
{ "resources": [
    { "uri": "sslcat://config/current",    "name": "Current sslcat configuration (redacted)", "mimeType": "application/json" },
    { "uri": "sslcat://metrics/snapshot",  "name": "Runtime metrics snapshot", "mimeType": "application/json" }
] }

// resources/templates/list 返回模板 URI
{ "resourceTemplates": [
    { "uriTemplate": "sslcat://logs/access{?since,domain,limit}", "name": "Access log tail", "mimeType": "text/plain" }
] }
```

### `sslcat://config/current`（scope=read）

返回当前配置的**脱敏快照**——字段名含 `password / secret / token / api_key / private_key / totp / auth_key / token_hash` 等子串的值会被替换为 `"***"`。脱敏只动一份深拷贝，运行时配置不受影响。

### `sslcat://metrics/snapshot`（scope=read）

```json
{
  "app": "sslcat",
  "version": "2.1.0-rc8",
  "server_time": "...",
  "sites_total": 12,
  "sites_enabled": 10,
  "static_sites": 1,
  "php_sites": 0,
  "cluster_mode": "standalone",
  "certs_total": 11,
  "certs_expiring_in_30d": 2,
  "proxy_stats": { ... },
  "mcp_tasks_total": 3,
  "mcp_tasks_by_status": { "succeeded": 2, "running": 1 }
}
```

比 `/metrics` Prometheus 文本更适合 AI 直接解读。

### `sslcat://logs/access{?since,domain,limit}`（scope=read）

读访问日志尾部，按时间窗口 / 域名 / 行数过滤。

- `since` —— 接受 duration（`10m` / `1h` / `30s`）或 RFC3339 绝对时间；
- `domain` —— 简单子串过滤（不区分大小写）；
- `limit` —— 行数上限，默认 200，最大 2000。

例：

```
sslcat://logs/access?since=10m&domain=api.example.com&limit=100
```

返回 `text/plain`，前两行是注释 header（路径、过滤参数），其余每行一条原始日志。解析行首时间戳支持 nginx 默认格式与 RFC3339；解析不出来时**保守保留**（避免静默丢日志）。

---

## Prometheus 指标（v2.1.0-rc4+）

启用 MCP 后自动暴露（与现有 sslcat 指标共用 `/metrics`）：

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `sslcat_mcp_requests_total` | counter | `tool, status` | tool 调用总次数。`status`: `ok / tool_error / error / forbidden / pending_confirm` |
| `sslcat_mcp_request_duration_seconds` | histogram | `tool` | tool 调用耗时（秒） |
| `sslcat_mcp_destructive_pending_confirmations` | gauge | — | 当前等待二次确认的 destructive 调用数 |

---

## 客户端接入示例

### Claude Desktop / Cursor 等支持 Streamable HTTP 的客户端

在客户端的 MCP 配置中添加：

```json
{
  "mcpServers": {
    "sslcat": {
      "type": "http",
      "url": "https://<your-host>/sslcat-panel/mcp/stream",
      "headers": {
        "Authorization": "Bearer sslcat_mcp_xxxxxxxx…"
      }
    }
  }
}
```

不同客户端字段名可能略有差异，按各自文档调整即可，关键是 `url + headers` 两项。

### 命令行直连（用于排查）

```bash
TOKEN=sslcat_mcp_xxxxxxxx…

# initialize（必须先做，服务端会下发 Mcp-Session-Id）
curl -isS https://localhost/sslcat-panel/mcp/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"curl","version":"1"}}}'

# 拿到响应头里的 Mcp-Session-Id，再调 tools/list：
SID=<上一步返回的 session id>
curl -sS https://localhost/sslcat-panel/mcp/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Mcp-Session-Id: $SID" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

---

## 安全建议

1. **不要把 MCP 端点暴露到公网**。即便有 token，仍推荐：
   - 配合 `tokens[].ip_allowlist` 限制 IP；
   - 放在 VPN / 内网 / Cloudflare Access 之类的零信任层之后。
2. **token 最小权限**。给 AI 助手默认只发 `read`；写类操作另发一个独立 token，并设置过期。
3. **审计**。`./data/mcp_audit.YYYYMMDD.log` 会记录每次 tool 调用（参数已脱敏）。
4. **定期轮换 token**：`sslcat mcp token revoke --name xxx` + `create`。

---

## 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| `401 unauthorized` | token 错 / 缺 Authorization 头 | 重新 `sslcat mcp token create` |
| `403 forbidden: ip not in allowlist` | 客户端 IP 不在 token 白名单 | 调整 `ip_allowlist` |
| `400 missing or unknown Mcp-Session-Id` | 没先调 initialize，或 session 已过期（30 分钟空闲） | 重新走 initialize 拿新 sessionId |
| `-32002 scope required: site:write` | token scope 不够 | 升级 token scope |
| 健康检查 200，但 stream 始终连不上 | 端口或反向代理路径错 | 看 sslcat 启动日志 `MCP service mounted at ...` |

---

## 后续路线（P2+）

- **P2**：站点 CRUD + destructive 二次确认 + Prometheus 指标
- **P3**：证书 CRUD + 长任务进度通知
- **P4**：转发 CRUD + Resources（config/logs/metrics）
- **P5**：前端 token 管理页 + Ruby 端到端测试 + 多客户端接入文档 + 正式 v2.1.0

详见 CHANGELOG 与 product-overview.md。
