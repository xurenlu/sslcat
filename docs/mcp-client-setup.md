# sslcat MCP 客户端接入示例（v2.1.0+）

把下面这套连接信息交给任意支持 MCP 的 AI 客户端，AI 就能直接管理 sslcat。

> 共同前提：
> 1. 已用 `sslcat mcp enable` 启用 MCP（或在管理后台「MCP」页面点开关）；
> 2. 已颁发一个 token（CLI: `sslcat mcp token create --name <n> --scopes read,site:write,cert:write,proxy:write` 或在管理后台「MCP」页面"创建 Token"按钮）；
> 3. 知道 sslcat 的对外 URL，例如 `https://your-host.example.com`。
>
> 默认 MCP 端点：`https://your-host.example.com/sslcat-panel/mcp/stream`。

---

## Claude Desktop

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或对应路径，加：

```json
{
  "mcpServers": {
    "sslcat": {
      "type": "http",
      "url": "https://your-host.example.com/sslcat-panel/mcp/stream",
      "headers": {
        "Authorization": "Bearer sslcat_mcp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      }
    }
  }
}
```

重启 Claude Desktop。在聊天框输入"列出我所有的反代站点"——Claude 就会调 `site_list` 工具。

---

## Cursor

设置 → MCP Servers → Add Server，类型选 HTTP。如果走 JSON：

```json
{
  "mcpServers": {
    "sslcat": {
      "url": "https://your-host.example.com/sslcat-panel/mcp/stream",
      "headers": {
        "Authorization": "Bearer sslcat_mcp_xxxxxxxx…"
      }
    }
  }
}
```

---

## Cherry Studio

设置 → MCP 服务器 → 添加，传输方式选 `Streamable HTTP`：

- **URL**：`https://your-host.example.com/sslcat-panel/mcp/stream`
- **Headers**：`Authorization: Bearer sslcat_mcp_xxxxxxxx…`

保存后在对话里选用 sslcat 服务即可。

---

## Continue.dev（VS Code 插件）

在 `~/.continue/config.json` 加：

```json
{
  "mcpServers": [
    {
      "name": "sslcat",
      "transport": "http",
      "url": "https://your-host.example.com/sslcat-panel/mcp/stream",
      "headers": {
        "Authorization": "Bearer sslcat_mcp_xxxxxxxx…"
      }
    }
  ]
}
```

---

## curl 手工调试（不依赖任何客户端）

帮助排查"是不是 sslcat 这边的事"：

```bash
TOKEN=sslcat_mcp_xxxxxxxx…
HOST=https://localhost   # 或者你的对外 host
BASE=$HOST/sslcat-panel/mcp/stream

# 1. 健康检查
curl -sk $HOST/sslcat-panel/mcp/health
# → {"status":"ok","protocol":"2025-06-18"}

# 2. initialize（拿到 Mcp-Session-Id）
SID=$(curl -sk -D - $BASE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"curl","version":"1"}}}' \
  | awk '/^Mcp-Session-Id:/ {print $2}' | tr -d '\r\n')
echo "session = $SID"

# 3. 列出工具
curl -sk $BASE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Mcp-Session-Id: $SID" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq .

# 4. 调一个只读工具
curl -sk $BASE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Mcp-Session-Id: $SID" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"site_list","arguments":{}}}' | jq .

# 5. 列出可读 resource
curl -sk $BASE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Mcp-Session-Id: $SID" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"resources/list"}' | jq .

# 6. 读访问日志最近 10 分钟
curl -sk $BASE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Mcp-Session-Id: $SID" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"sslcat://logs/access?since=10m&limit=50"}}' | jq -r .result.contents[0].text

# 7. 读近期内部错误
curl -sk $BASE \
  -H "Authorization: Bearer $TOKEN" \
  -H "Mcp-Session-Id: $SID" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"sslcat://logs/error?id=internal&keyword=ERROR&since=10m&limit=50"}}' | jq -r .result.contents[0].text
```

---

## 常见踩坑

| 现象 | 排查 |
|---|---|
| `401 unauthorized` | token 错；或忘记加 `Authorization: Bearer ` 前缀 |
| `400 missing or unknown Mcp-Session-Id` | 没先 `initialize` 就调 `tools/call`，或者 session 30 分钟空闲被 GC 了，重新 initialize |
| `-32002 scope required: site:write` | 当前 token scope 不够，去管理后台或 CLI 加 scope 重新发一个 |
| `-32003 rate limited` | 触发了 token 的 `rate_limit`，降低调用频率或调高限速 |
| 自签证书导致客户端拒连 | 临时用 `-k`（curl）或在客户端开"信任自签"；生产请走真证书 |
| Claude Desktop 看不到工具 | 重启 Claude Desktop（macOS：Cmd-Q）；改配置后必须重启 |

更详细的协议说明、工具清单与权限模型见 [`docs/mcp.md`](./mcp.md)。
