# SSLcat v1.2.0 版本发布说明

**发布日期**: 2025-01-15  
**版本类型**: 重大功能更新  
**主要特性**: DNS验证SSL证书申请 + 代理访问控制

---

## 🎯 版本概述

SSLcat v1.2.0 是一个重大功能更新版本，主要引入了两个核心功能：

1. **完整的DNS验证SSL证书申请系统** - 支持多种DNS服务商，实现自动化证书申请
2. **代理访问控制功能** - 为代理规则添加密码保护，提升安全性

这些功能使得SSLcat能够处理更复杂的SSL证书申请场景，并为代理服务提供额外的安全保护。

---

## 🚀 主要新功能

### 1. DNS验证SSL证书申请系统

#### 支持的DNS服务商
- **Cloudflare** - 完整实现，支持API Token认证
- **阿里云DNS** - 完整实现，支持HMAC-SHA1签名认证
- **腾讯云DNS** - 完整实现，支持腾讯云API签名认证
- **GoDaddy** - 完整实现，支持SSO Key认证
- **自定义API** - 完整实现，支持通用HTTP API调用
- **AWS Route53** - 框架已搭建，待实现具体API调用

#### 技术特性
- **统一接口设计**: 所有DNS服务商实现统一的`DNSProviderInterface`接口
- **自动DNS记录管理**: 自动创建、更新、删除TXT记录
- **DNS传播监控**: 智能等待DNS记录传播完成
- **通配符证书支持**: 支持`*.example.com`类型的通配符证书申请
- **多服务商支持**: 可同时配置多个DNS服务商，支持故障转移

#### 认证机制
- **Cloudflare**: Bearer Token认证
- **阿里云**: HMAC-SHA1签名认证，符合阿里云API规范
- **腾讯云**: 腾讯云API签名认证，符合腾讯云API规范
- **GoDaddy**: SSO Key认证
- **自定义**: Bearer Token认证（可选）

### 2. 代理访问控制功能

#### 核心功能
- **密码保护**: 为代理规则添加用户名/密码验证
- **多用户支持**: 支持配置多个用户名/密码组合
- **会话管理**: 可配置的会话超时时间
- **Cookie域控制**: 支持自定义Cookie域名设置
- **登录页面**: 自动生成美观的登录界面

#### 安全特性
- **会话安全**: 使用安全的Session ID管理
- **密码验证**: 支持明文密码验证（内部使用）
- **自动清理**: 过期会话自动清理机制
- **条件启用**: 只有开启认证才能设置用户密码

---

## 🔧 技术实现

### DNS验证系统架构

```
SSL Manager
    ↓
DNS Provider Manager
    ↓
┌─────────────────┬─────────────────┬─────────────────┐
│  Cloudflare     │   阿里云DNS     │   腾讯云DNS     │
│  Provider       │   Provider      │   Provider      │
└─────────────────┴─────────────────┴─────────────────┘
    ↓
DNS API Calls
    ↓
TXT Record Management
```

### 代理访问控制架构

```
HTTP Request
    ↓
Proxy Middleware
    ↓
Auth Check
    ↓
┌─────────────────┬─────────────────┐
│  已认证用户     │   未认证用户    │
│  (直接代理)     │  (显示登录页)   │
└─────────────────┴─────────────────┘
```

### 核心组件

#### DNS Provider Interface
```go
type DNSProviderInterface interface {
    SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error
    DeleteTXTRecord(ctx context.Context, domain, name string) error
    GetTXTRecord(ctx context.Context, domain, name string) (string, error)
    WaitForPropagation(ctx context.Context, domain, name, value string) error
    GetProviderName() string
    Validate() error
}
```

#### Proxy Auth Manager
```go
type ProxyAuthManager struct {
    sessions map[string]*AuthSession
    log      Logger
}
```

---

## 📋 配置说明

### DNS服务商配置

#### Cloudflare配置
```json
{
  "name": "my-cloudflare",
  "type": "cloudflare",
  "enabled": true,
  "api_key": "your-api-token",
  "zone_id": "your-zone-id",
  "priority": 1
}
```

#### 阿里云DNS配置
```json
{
  "name": "my-aliyun",
  "type": "aliyun",
  "enabled": true,
  "api_key": "your-access-key-id",
  "api_secret": "your-access-key-secret",
  "priority": 2
}
```

#### 腾讯云DNS配置
```json
{
  "name": "my-tencent",
  "type": "tencent",
  "enabled": true,
  "api_key": "your-secret-id",
  "api_secret": "your-secret-key",
  "priority": 3
}
```

### 代理访问控制配置

```json
{
  "domain": "example.com",
  "target": "http://backend:8080",
  "port": 443,
  "enabled": true,
  "ssl_only": true,
  "auth_enabled": true,
  "auth_users": [
    {
      "username": "admin",
      "password": "password123"
    }
  ],
  "auth_session_timeout": 3600,
  "auth_cookie_domain": ".example.com"
}
```

---

## 🎨 用户界面

### DNS配置管理界面
- **服务商列表**: 显示所有配置的DNS服务商及其状态
- **添加服务商**: 支持所有服务商类型的配置表单
- **编辑服务商**: 修改现有服务商的配置
- **全局配置**: 设置默认服务商和验证方式
- **状态监控**: 实时显示服务商状态和配置信息

### 代理访问控制界面
- **认证开关**: 简单的开关控制是否启用认证
- **用户管理**: 动态添加/删除用户名密码组合
- **会话配置**: 设置会话超时时间和Cookie域名
- **登录页面**: 自动生成的美观登录界面

---

## 🔒 安全考虑

### DNS服务商安全
- **API密钥加密存储**: 所有API密钥在配置中加密存储
- **权限最小化**: 只请求必要的DNS操作权限
- **错误处理**: 统一的错误处理和日志记录
- **超时控制**: 所有API调用都有超时控制

### 代理访问控制安全
- **会话安全**: 使用安全的Session ID生成
- **密码保护**: 支持强密码策略
- **自动清理**: 过期会话自动清理
- **Cookie安全**: 支持安全的Cookie设置

---

## 📊 性能优化

### DNS操作优化
- **并发控制**: 支持多个DNS服务商并发操作
- **缓存机制**: DNS记录查询结果缓存
- **重试机制**: 自动重试失败的API调用
- **超时优化**: 合理的超时设置避免长时间等待

### 代理认证优化
- **会话缓存**: 内存中的会话缓存提升性能
- **异步清理**: 后台异步清理过期会话
- **最小化验证**: 只在需要时进行认证检查

---

## 🧪 测试覆盖

### DNS服务商测试
- **单元测试**: 每个DNS服务商的API调用测试
- **集成测试**: 完整的DNS验证流程测试
- **错误处理测试**: 各种错误场景的测试
- **并发测试**: 多服务商并发操作测试

### 代理认证测试
- **认证流程测试**: 完整的登录认证流程测试
- **会话管理测试**: 会话创建、验证、过期测试
- **多用户测试**: 多用户并发访问测试
- **安全测试**: 各种安全攻击场景测试

---

## 🚀 使用场景

### DNS验证适用场景
1. **内网服务器**: 无法开放80/443端口的服务器
2. **通配符证书**: 需要`*.example.com`类型的证书
3. **多域名证书**: 需要包含多个域名的证书
4. **自动化部署**: 需要自动化证书申请和续期

### 代理访问控制适用场景
1. **内部服务保护**: 保护内部API或服务
2. **临时访问控制**: 为特定服务添加临时密码保护
3. **多租户环境**: 不同用户访问不同的后端服务
4. **开发环境**: 保护开发中的服务不被外部访问

---

## 🔄 升级指南

### 从v1.1.x升级到v1.2.0

1. **备份配置**: 升级前备份现有配置文件
2. **停止服务**: 停止当前运行的SSLcat服务
3. **替换二进制**: 下载并替换新的二进制文件
4. **配置迁移**: 新版本会自动处理配置格式变更
5. **启动服务**: 启动新版本服务
6. **验证功能**: 验证DNS配置和代理认证功能

### 配置迁移说明
- **DNS配置**: 新版本会自动创建DNS配置结构
- **代理配置**: 现有代理规则保持不变，可选择性启用认证
- **SSL配置**: 现有SSL配置完全兼容

---

## 🐛 已知问题

### DNS服务商限制
1. **AWS Route53**: 目前只提供框架，具体API调用待实现
2. **阿里云API**: 需要确保Access Key有DNS操作权限
3. **腾讯云API**: 需要确保Secret Key有DNS操作权限

### 代理认证限制
1. **密码存储**: 目前使用明文存储，建议定期更换密码
2. **会话持久化**: 重启服务后所有会话会丢失
3. **多实例**: 多实例部署时会话不共享

---

## 🔮 未来规划

### 短期计划 (v1.2.1)
- 实现AWS Route53完整API支持
- 添加更多DNS服务商支持
- 优化DNS传播等待机制
- 添加代理认证的密码加密存储

### 中期计划 (v1.3.0)
- 支持更多认证方式（OAuth、LDAP等）
- 添加代理认证的审计日志
- 实现DNS服务商的健康检查
- 添加证书申请的批量操作

### 长期计划 (v2.0.0)
- 完全重构的微服务架构
- 支持Kubernetes部署
- 添加更多云服务商集成
- 实现高级的访问控制策略

---

## 📞 技术支持

### 问题反馈
- **GitHub Issues**: 在GitHub仓库提交问题
- **文档**: 查看完整的用户文档和API文档
- **社区**: 加入SSLcat用户社区讨论

### 贡献指南
- **代码贡献**: 欢迎提交Pull Request
- **文档贡献**: 帮助完善文档和示例
- **测试贡献**: 帮助测试新功能和报告问题

---

## 📄 许可证

SSLcat v1.2.0 继续使用 MIT 许可证，详情请查看 LICENSE 文件。

---

**感谢所有为SSLcat v1.2.0做出贡献的开发者和用户！**
