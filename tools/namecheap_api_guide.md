# Namecheap API 获取指南

## 1. 获取 Namecheap API Key 的步骤

### 步骤 1: 登录 Namecheap 账户
1. 访问 [Namecheap 官网](https://www.namecheap.com/)
2. 点击右上角的 "Sign In" 登录你的账户
3. 如果没有账户，请先注册

### 步骤 2: 进入 API 设置页面
1. 登录后，点击右上角的用户名
2. 选择 "Profile" 进入个人资料页面
3. 在左侧菜单中找到 "Tools" 选项卡
4. 在 "Business & Dev Tools" 部分找到 "Namecheap API Access"
5. 点击 "Manage" 进入 API 管理页面

### 步骤 3: 启用 API 访问
1. 在 API 设置页面，找到 "API Access" 选项
2. 点击 "Enable" 启用 API 访问
3. 阅读并同意 API 使用条款

### 步骤 4: 获取 API 凭据
启用 API 访问后，你将获得以下信息：
- **API Key**: 你的 API 密钥
- **API User**: 你的用户名（通常是你的 Namecheap 用户名）
- **Client IP**: 你的公网 IP 地址

## 2. 配置 SSLcat 使用 Namecheap

### 在 sslcat.conf 中配置：
```json
{
  "name": "namecheap-dns",
  "type": "namecheap",
  "enabled": true,
  "api_key": "你的API_KEY",
  "api_secret": "你的API_USER",
  "zone_id": "你的CLIENT_IP",
  "priority": 5
}
```

### 参数说明：
- `api_key`: 你的 Namecheap API Key
- `api_secret`: 你的 Namecheap 用户名（API User）
- `zone_id`: 你的公网 IP 地址（Client IP）

## 3. 注意事项

### API 限制：
- Namecheap API 有请求频率限制
- 每个 IP 地址每分钟最多 20 个请求
- 需要将你的服务器 IP 地址添加到白名单

### 安全建议：
1. 妥善保存你的 API Key
2. 不要将 API Key 提交到代码仓库
3. 定期更换 API Key
4. 只给必要的权限

## 4. 测试 Namecheap API

你可以使用以下命令测试 Namecheap API 是否正常工作：

```bash
# 运行 Namecheap DNS 测试
go run tools/test_dns_providers.go
```

## 5. 常见问题

### Q: 为什么需要 Client IP？
A: Namecheap API 需要验证请求来源的 IP 地址，这是安全措施。

### Q: API Key 在哪里找到？
A: 在 Namecheap 账户的 "Profile" -> "Tools" -> "Namecheap API Access" 页面。

### Q: 如何获取我的公网 IP？
A: 你可以访问 https://whatismyipaddress.com/ 或使用命令 `curl ifconfig.me` 获取。

## 6. 支持的 API 功能

Namecheap API 支持以下 DNS 操作：
- ✅ 获取域名列表
- ✅ 获取 DNS 记录
- ✅ 创建 TXT 记录
- ✅ 更新 TXT 记录
- ✅ 删除 TXT 记录
- ✅ 等待 DNS 传播

## 7. 配置示例

完整的 Namecheap DNS 配置示例：

```json
{
  "ssl": {
    "dns_providers": [
      {
        "name": "namecheap-dns",
        "type": "namecheap",
        "enabled": true,
        "api_key": "your_namecheap_api_key",
        "api_secret": "your_namecheap_username",
        "zone_id": "your_public_ip_address",
        "priority": 5
      }
    ],
    "default_dns_provider": "namecheap-dns"
  }
}
```
