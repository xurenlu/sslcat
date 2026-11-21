# 证书续期功能测试指南

## 功能概述

本次更新为证书续期功能添加了以下改进：

1. **SSE实时进度推送**：证书续期时，用户可以实时看到续期进度
2. **增强的日志记录**：后端记录详细的证书续期过程，包括旧证书和新证书的有效期对比
3. **强制缓存刷新**：续期成功后强制刷新证书缓存，确保返回最新证书信息
4. **改进的错误提示**：续期失败时显示详细的错误原因

## 实现的改动

### 后端改动

1. **新增API接口**：`/api/ssl/retry-stream`
   - 文件：`internal/web/api_ssl.go`
   - 功能：支持SSE流式进度推送的证书续期接口

2. **增强日志记录**：`internal/ssl/manager.go`
   - 在 `EnsureDomainCert` 开始时记录旧证书的有效期
   - 在证书保存到磁盘时记录文件路径和新证书有效期
   - 在证书加载到缓存时验证证书有效期
   - 添加新旧证书有效期对比日志

3. **强制缓存刷新**：`internal/ssl/manager.go`
   - 证书保存成功后，先清除旧缓存
   - 从磁盘重新加载证书
   - 验证加载的证书有效期

4. **路由注册**：`internal/web/server.go`
   - 注册新的 `/api/ssl/retry-stream` 路由

### 前端改动

1. **改造续期函数**：`frontend/src/pages/SSLManagement.tsx`
   - `renewCertificate` 函数改为调用 `/api/ssl/retry-stream` API
   - 支持SSE事件接收和处理
   - 添加续期进度对话框

2. **新增UI组件**
   - 续期进度对话框（Modal）
   - 实时进度条
   - 进度事件列表
   - 错误提示区域

## 测试步骤

### 准备工作

1. 确保已编译最新代码：
```bash
cd /Users/rocky/Sites/sslcat
make build
```

2. 启动服务（需要root权限）：
```bash
sudo ./build/sslcat
```

3. 打开浏览器访问管理面板：
```
https://s2.shifen.de/sslcat-panel/
```

### 测试场景1：正常续期流程

1. 在SSL证书管理页面，找到一个即将过期的证书（如 `83d.me`）
2. 点击该证书行的"刷新"按钮（🔄图标）
3. 观察续期进度对话框是否弹出
4. 检查进度对话框中的内容：
   - 域名显示是否正确
   - 进度条是否实时更新
   - 进度事件列表是否显示详细步骤
5. 等待续期完成
6. 检查成功提示是否显示
7. 等待3秒后，证书列表应自动刷新
8. 验证证书的有效期是否更新为新的日期

### 测试场景2：续期失败处理

1. 选择一个无法续期的域名（如DNS未解析到服务器的域名）
2. 点击"刷新"按钮
3. 观察进度对话框中的错误提示
4. 检查错误信息是否详细且有帮助
5. 验证失败后对话框是否可以关闭

### 测试场景3：后端日志验证

1. 在续期过程中，查看服务器日志：
```bash
tail -f /var/log/sslcat/sslcat.log
```

2. 检查日志中是否包含以下信息：
   - `Certificate request initiated for domain: xxx`
   - `Existing certificate found for xxx: NotBefore=..., NotAfter=..., DaysRemaining=...`
   - `New certificate obtained for xxx: NotBefore=..., NotAfter=..., ValidDays=...`
   - `Certificate saved to disk: cert=..., key=...`
   - `Reloading certificate from disk to ensure cache is up-to-date: xxx`
   - `Certificate successfully loaded from disk to cache: xxx`
   - `Loaded certificate verification for xxx: NotAfter=..., DaysRemaining=...`

### 测试场景4：缓存刷新验证

1. 续期证书前，记录证书的过期时间
2. 完成续期后，立即刷新页面
3. 验证证书列表中显示的过期时间是否已更新
4. 如果有API工具（如curl），可以直接调用证书列表API验证：
```bash
curl -s 'https://s2.shifen.de/sslcat-panel/api/ssl-certs' \
  -H 'Cookie: your-session-cookie' | jq
```

## 预期结果

### 成功续期

- ✅ 进度对话框实时显示续期步骤
- ✅ 进度条从0%增长到100%
- ✅ 显示"证书续期成功"提示
- ✅ 3秒后自动刷新证书列表
- ✅ 证书有效期更新为新的日期（通常是90天后）
- ✅ 后端日志记录完整的续期过程

### 续期失败

- ✅ 进度对话框显示失败原因
- ✅ 错误提示清晰且有帮助
- ✅ 可以关闭对话框
- ✅ 证书列表保持不变
- ✅ 后端日志记录失败原因

## 常见问题排查

### 问题1：续期成功但证书有效期未更新

**可能原因**：
- 缓存未正确刷新
- 前端缓存问题

**排查步骤**：
1. 检查后端日志，确认证书是否真的续期成功
2. 查看日志中的 `Loaded certificate verification` 行，确认加载的证书有效期
3. 强制刷新浏览器（Ctrl+F5 或 Cmd+Shift+R）
4. 清除浏览器缓存后重试

### 问题2：续期进度对话框不显示

**可能原因**：
- 前端代码未正确编译
- API路由未注册

**排查步骤**：
1. 检查浏览器控制台是否有错误
2. 检查网络请求，确认是否调用了 `/api/ssl/retry-stream`
3. 重新编译前端代码：
```bash
cd frontend
yarn build
```

### 问题3：SSE连接失败

**可能原因**：
- 网络代理问题
- 服务器不支持SSE

**排查步骤**：
1. 检查浏览器控制台的网络请求
2. 确认响应头包含 `Content-Type: text/event-stream`
3. 检查是否有中间代理干扰SSE连接

## 测试清单

- [ ] 正常续期流程测试通过
- [ ] 续期失败处理测试通过
- [ ] 后端日志记录完整
- [ ] 缓存刷新验证通过
- [ ] 进度对话框UI正常显示
- [ ] SSE实时推送工作正常
- [ ] 错误提示清晰有帮助
- [ ] 证书有效期正确更新

## 注意事项

1. **测试环境**：建议在测试环境中进行测试，避免影响生产环境
2. **证书配额**：Let's Encrypt有速率限制，避免频繁测试同一域名
3. **权限要求**：sslcat需要root权限运行以绑定80/443端口
4. **DNS要求**：测试域名必须正确解析到服务器IP

## 后续改进建议

1. 添加续期历史记录功能
2. 支持批量续期
3. 添加续期失败自动重试机制
4. 提供更详细的诊断工具

