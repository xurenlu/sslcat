# 机器人检测 API 安全增强

## 问题描述

在初始实现中，机器人检测的 API 接口使用了与管理面板相同的路径前缀（如 `/sslcat-panel/api/bot-detection/*`），这存在安全隐患：

1. **路径暴露**：当触发机器人检测时，攻击者可能通过错误信息或网络请求发现管理面板的路径
2. **攻击面扩大**：暴露的管理路径可能成为攻击目标
3. **信息泄露**：攻击者可以推断出系统使用的管理面板路径规则

## 解决方案

### 1. 随机 API 前缀

为机器人检测 API 生成一个随机的、不可预测的路径前缀，与管理面板路径完全分离。

#### 实现细节

**配置生成** (`internal/config/config.go`):

```go
// generateBotAPIPrefix 生成随机的机器人检测 API 前缀
func generateBotAPIPrefix() string {
    // 生成 16 字节随机数据
    data := make([]byte, 16)
    _, err := rand.Read(data)
    if err != nil {
        data = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
    }
    hash := sha256.Sum256(data)
    // 使用前 12 个字符作为前缀
    return "/bot-" + hex.EncodeToString(hash[:6])
}
```

生成的前缀示例：
- `/bot-a3f2d8c9e1b4`
- `/bot-7b9e4f1c2a6d`
- `/bot-5d8a3c7f9e2b`

**配置存储**:

```json
{
  "admin_prefix": "/sslcat-panel",
  "bot_api_prefix": "/bot-a3f2d8c9e1b4"
}
```

### 2. 路由分离

机器人检测 API 使用独立的随机前缀，与管理面板路径完全分离：

```
管理面板 API:
  /sslcat-panel/api/proxy-rules
  /sslcat-panel/api/ssl-certs
  /sslcat-panel/api/stats
  ...

机器人检测 API (随机前缀):
  /bot-a3f2d8c9e1b4/config
  /bot-a3f2d8c9e1b4/stats
  /bot-a3f2d8c9e1b4/whitelist
  /bot-a3f2d8c9e1b4/logs

机器人验证接口 (公开):
  /bot-challenge/verify
  /bot-challenge/refresh
```

### 3. 前端动态获取

前端组件在运行时动态获取 Bot API 前缀，而不是硬编码：

**API 接口** (`internal/web/api_config.go`):

```go
// GET /sslcat-panel/api/config/bot-api-prefix
func (s *Server) handleAPIConfigBotAPIPrefix(w http.ResponseWriter, r *http.Request) {
    if !s.authorizeAPI(w, r, true) {
        return
    }
    
    prefix := s.config.BotAPIPrefix
    if prefix == "" {
        prefix = "/bot-api" // 兼容旧配置
    }
    
    writeJSON(w, map[string]interface{}{
        "success": true,
        "prefix":  prefix,
    })
}
```

**前端实现** (`frontend/src/components/BotDetectionConfig.tsx`):

```typescript
const [botAPIPrefix, setBotAPIPrefix] = useState<string>('')

useEffect(() => {
  loadBotAPIPrefix()
}, [])

const loadBotAPIPrefix = async () => {
  const response = await fetch(buildApiPath('/api/config/bot-api-prefix'), {
    credentials: 'include',
  })
  const data = await response.json()
  if (data.success && data.prefix) {
    setBotAPIPrefix(data.prefix)
  }
}

// 使用动态前缀
const loadConfig = async () => {
  const response = await fetch(buildApiPath(`${botAPIPrefix}/config?domain=${domain}`), {
    credentials: 'include',
  })
  // ...
}
```

## 安全优势

### 1. 路径隐藏

- 随机前缀无法通过常规手段猜测
- 每个实例的前缀都不同
- 攻击者无法通过机器人检测推断管理面板路径

### 2. 攻击面缩小

- 管理面板路径不会暴露给普通用户
- 机器人检测 API 与管理功能完全隔离
- 即使机器人检测 API 被发现，也不会影响管理面板安全

### 3. 可追溯性

- 每次启动时在日志中记录 Bot API 前缀
- 管理员可以查看日志了解当前使用的前缀
- 便于调试和监控

```
2025-01-01 12:00:00 INFO Bot Detection API prefix: /bot-a3f2d8c9e1b4
```

## 兼容性

### 向后兼容

- 旧配置文件会自动生成随机前缀
- 如果配置中没有 `bot_api_prefix`，会在启动时自动生成
- 前端会自动适配新的 API 路径

### 配置迁移

首次启动时，系统会自动：

1. 检测配置中是否有 `bot_api_prefix`
2. 如果没有，生成一个随机前缀
3. 将前缀保存到配置文件
4. 在日志中记录生成的前缀

## 使用说明

### 管理员

1. **查看 Bot API 前缀**：
   - 查看启动日志：`grep "Bot Detection API prefix" data/sslcat.log`
   - 或通过管理面板 API 查询：`GET /sslcat-panel/api/config/bot-api-prefix`

2. **重新生成前缀**（如果需要）：
   - 从配置文件中删除 `bot_api_prefix` 字段
   - 重启 sslcat
   - 系统会自动生成新的随机前缀

3. **手动设置前缀**（不推荐）：
   ```json
   {
     "bot_api_prefix": "/my-custom-prefix"
   }
   ```

### 开发者

前端开发时，使用动态前缀：

```typescript
// ❌ 错误：硬编码路径
fetch('/api/bot-detection/config')

// ✅ 正确：使用动态前缀
const botAPIPrefix = await loadBotAPIPrefix()
fetch(`${botAPIPrefix}/config`)
```

## 测试验证

### 1. 验证前缀随机性

```bash
# 启动 sslcat 多次，检查日志中的前缀是否不同
for i in {1..5}; do
  rm data/sslcat.conf  # 删除配置
  ./sslcat &
  sleep 2
  grep "Bot Detection API prefix" logs/sslcat.log
  pkill sslcat
done
```

### 2. 验证 API 可访问性

```bash
# 获取 Bot API 前缀
PREFIX=$(curl -s http://localhost/sslcat-panel/api/config/bot-api-prefix \
  -H "Cookie: session=xxx" | jq -r '.prefix')

# 使用前缀访问 API
curl -s "http://localhost${PREFIX}/stats" \
  -H "Cookie: session=xxx"
```

### 3. 验证路径隔离

```bash
# 尝试使用管理路径访问机器人 API（应该失败）
curl -s http://localhost/sslcat-panel/api/bot-detection/config \
  -H "Cookie: session=xxx"
# 预期：404 Not Found

# 使用正确的随机前缀（应该成功）
curl -s "http://localhost${PREFIX}/config" \
  -H "Cookie: session=xxx"
# 预期：返回配置数据
```

## 性能影响

- **启动时间**：增加约 1-2ms（生成随机前缀）
- **运行时开销**：无额外开销
- **内存占用**：增加约 50 字节（存储前缀字符串）

## 安全建议

1. **定期轮换**：建议每 3-6 个月重新生成 Bot API 前缀
2. **日志保护**：确保日志文件访问权限受限，避免前缀泄露
3. **监控异常**：监控对旧前缀的访问尝试，可能表示攻击行为
4. **HTTPS 必须**：始终使用 HTTPS，避免前缀在网络传输中泄露

## 相关文件

- `internal/config/config.go` - 配置结构和前缀生成
- `internal/web/server.go` - 路由注册
- `internal/web/api_config.go` - 前缀查询 API
- `internal/web/api_bot_detection.go` - 机器人检测 API
- `frontend/src/components/BotDetectionConfig.tsx` - 前端组件

## 更新日志

### v1.4.1 (2025-01-01)

- ✅ 添加随机 Bot API 前缀生成
- ✅ 分离机器人检测 API 和管理面板路径
- ✅ 前端动态获取 API 前缀
- ✅ 添加前缀查询 API
- ✅ 更新文档和测试

## 总结

通过使用随机生成的 API 前缀，我们成功地：

1. **隐藏了管理面板路径**：攻击者无法通过机器人检测推断管理面板位置
2. **提高了安全性**：减少了攻击面和信息泄露风险
3. **保持了易用性**：前端自动适配，管理员无需手动配置
4. **确保了兼容性**：旧配置自动升级，无需手动迁移

这是一个简单但有效的安全增强措施，显著提高了系统的整体安全性。

