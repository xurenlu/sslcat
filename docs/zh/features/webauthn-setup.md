# WebAuthn 指纹登录功能设置指南

## 概述

WebAuthn（Web Authentication）是一个 W3C 标准，允许用户使用生物识别（如指纹、Face ID）或设备 PIN 来登录，无需输入密码。这提供了更安全和便捷的登录体验。

## 功能特性

- ✅ 支持指纹识别（Chrome、Edge、Safari）
- ✅ 支持 Face ID / Touch ID（macOS、iOS）
- ✅ 支持 Windows Hello
- ✅ 支持硬件安全密钥（如 YubiKey）
- ✅ 多设备管理：可以为同一账户注册多个设备
- ✅ 安全的公钥加密：私钥存储在设备安全区域，服务器只存储公钥

## 安装依赖

首先需要下载 WebAuthn 库：

```bash
cd /path/to/sslcat
go mod tidy
```

如果网络问题，可以使用代理：

```bash
export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890
go mod tidy
```

## 配置说明

WebAuthn 需要配置以下参数：

1. **RPID (Relying Party ID)**: 通常是你的域名（不含协议和端口）
   - 例如：`example.com` 或 `sslcat.example.com`
   - 不能是 `localhost`（生产环境）

2. **RPOrigin**: 完整的源地址
   - 例如：`https://sslcat.example.com` 或 `http://localhost:8080`（开发环境）

## 初始化 WebAuthn 管理器

在 `server.go` 的 `NewServer` 函数中添加 WebAuthn 管理器初始化：

```go
// 初始化 WebAuthn 管理器
webauthnManager, err := NewWebAuthnManager(
    log.WithField("component", "webauthn"),
    cfg.Server.DataDir,
    cfg.Server.Host, // 或配置专门的 RPID
    "https://"+cfg.Server.Host, // 或配置专门的 RPOrigin
)
if err != nil {
    log.Warnf("WebAuthn 初始化失败: %v", err)
    // 可以选择继续运行（WebAuthn 功能不可用）或退出
}
```

## 注册路由

在 `server.go` 的 `setupRoutes` 函数中添加：

```go
// WebAuthn API 路由
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/register/begin", s.handleAPIWebAuthnBeginRegistration)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/register/finish", s.handleAPIWebAuthnFinishRegistration)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/login/begin", s.handleAPIWebAuthnBeginLogin)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/login/finish", s.handleAPIWebAuthnFinishLogin)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/credentials", s.handleAPIWebAuthnListCredentials)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/credentials/delete", s.handleAPIWebAuthnDeleteCredential)
```

## 使用流程

### 1. 注册 WebAuthn 凭证

1. 登录管理面板
2. 进入设置页面
3. 找到"WebAuthn 指纹登录"部分
4. 点击"注册新设备"
5. 输入设备名称（如 "Chrome on MacBook"）
6. 浏览器会弹出指纹/生物识别验证
7. 完成验证后，设备已注册

### 2. 使用 WebAuthn 登录

1. 在登录页面，如果已注册 WebAuthn，会显示"使用指纹登录"按钮
2. 点击按钮
3. 浏览器弹出指纹/生物识别验证
4. 验证成功后自动登录

### 3. 管理已注册的设备

1. 在设置页面查看所有已注册的设备
2. 可以删除不再使用的设备

## 浏览器支持

- ✅ Chrome 67+
- ✅ Edge 18+
- ✅ Firefox 60+
- ✅ Safari 13+
- ✅ Opera 54+

## 安全注意事项

1. **HTTPS 要求**：生产环境必须使用 HTTPS，WebAuthn 在 HTTP 下不可用（localhost 除外）
2. **域名配置**：RPID 必须与实际访问域名匹配
3. **凭证备份**：建议保留密码登录作为备用方式
4. **设备丢失**：如果设备丢失，可以在其他设备上删除该设备的凭证

## 故障排查

### 问题：注册时提示"不支持 WebAuthn"

**解决方案**：
- 确保使用支持的浏览器
- 确保设备支持生物识别
- 确保使用 HTTPS（生产环境）

### 问题：登录时找不到凭证

**解决方案**：
- 检查是否在同一设备上注册
- 检查浏览器是否允许存储凭证
- 清除浏览器缓存后重试

### 问题：RPID 不匹配错误

**解决方案**：
- 确保 RPID 配置与实际访问域名一致
- 检查域名是否包含协议和端口

## API 文档

### 开始注册

```
POST /api/webauthn/register/begin
Content-Type: application/json

{
  "username": "admin",
  "device_name": "Chrome on MacBook"
}
```

### 完成注册

```
POST /api/webauthn/register/finish
Content-Type: application/json

{
  "session_key": "...",
  "response": {...},  // WebAuthn 响应对象
  "device_name": "Chrome on MacBook"
}
```

### 开始登录

```
POST /api/webauthn/login/begin
Content-Type: application/json

{
  "username": "admin"
}
```

### 完成登录

```
POST /api/webauthn/login/finish
Content-Type: application/json

{
  "username": "admin",
  "session_key": "...",
  "response": {...}  // WebAuthn 响应对象
}
```

## 前端实现

前端需要使用浏览器的 WebAuthn API：

```javascript
// 开始注册
const response = await fetch('/api/webauthn/register/begin', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', device_name: 'Chrome' })
});
const { options, session_key } = await response.json();

// 调用浏览器 WebAuthn API
const credential = await navigator.credentials.create({
  publicKey: options
});

// 完成注册
await fetch('/api/webauthn/register/finish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_key,
    response: credential,
    device_name: 'Chrome'
  })
});
```

## 待完成事项

- [ ] 在 NewServer 中初始化 WebAuthn 管理器
- [ ] 注册 WebAuthn API 路由
- [ ] 前端实现 WebAuthn 注册和登录 UI
- [ ] 在设置页面添加 WebAuthn 管理界面
- [ ] 在登录页面添加 WebAuthn 登录选项
- [ ] 测试各种浏览器和设备

