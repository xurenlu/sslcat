# Cloudflare API Token 获取指南

## 🎯 如何获取 Cloudflare API Token

### 方法 1: 使用 Custom Token (推荐)

#### 步骤 1: 登录 Cloudflare 控制台
1. 访问 [Cloudflare 控制台](https://dash.cloudflare.com/)
2. 使用你的账户登录

#### 步骤 2: 创建 Custom Token
1. 点击右上角的用户头像
2. 选择 **"My Profile"**
3. 在左侧菜单中找到 **"API Tokens"**
4. 点击 **"Create Token"**
5. 选择 **"Custom token"**

#### 步骤 3: 配置 Token 权限
在 Token 配置页面设置以下权限：

**Zone 权限:**
- `Zone:Read` - 读取域名信息
- `Zone:Edit` - 编辑 DNS 记录

**Account 权限:**
- `Account:Read` - 读取账户信息

**Zone Resources:**
- 选择 **"Include - All zones"** 或选择特定域名

#### 步骤 4: 创建并保存 Token
1. 点击 **"Continue to summary"**
2. 检查权限配置
3. 点击 **"Create Token"**
4. **重要**: 复制并保存 Token，它只会显示一次！

### 方法 2: 使用 Global API Key

#### 步骤 1: 获取 Global API Key
1. 在 **"My Profile"** → **"API Tokens"** 页面
2. 找到 **"API Keys"** 部分
3. 点击 **"View"** 查看 Global API Key
4. 复制 API Key

#### 步骤 2: 获取 Email
使用你的 Cloudflare 账户邮箱地址

## 🔧 配置 SSLcat 使用 Cloudflare

### 在 sslcat.conf 中配置：

```json
{
  "name": "cloudflare-dns",
  "type": "cloudflare",
  "enabled": true,
  "api_key": "你的API_TOKEN",
  "api_secret": "",
  "zone_id": "",
  "priority": 3
}
```

### 参数说明：
- `api_key`: 你的 Cloudflare API Token
- `api_secret`: 留空（Cloudflare 不需要）
- `zone_id`: 可选，留空会自动查找

## 🧪 测试 Cloudflare API

### 测试方法 1: 交互式测试
```bash
go run tools/test_cloudflare_interactive.go
```

### 测试方法 2: 直接 API 测试
```bash
go run tools/test_cloudflare_direct.go
```

### 测试方法 3: 完整功能测试
```bash
go run tools/test_cloudflare.go
```

## 📋 权限要求

Cloudflare API Token 需要以下权限：

### 必需权限：
- ✅ `Zone:Read` - 读取域名列表
- ✅ `Zone:Edit` - 创建/编辑/删除 DNS 记录

### 可选权限：
- ✅ `Account:Read` - 读取账户信息
- ✅ `User:Read` - 读取用户信息

## 🔍 常见问题

### Q: Token 权限不足怎么办？
A: 重新创建 Token，确保包含 `Zone:Read` 和 `Zone:Edit` 权限。

### Q: 如何获取 Zone ID？
A: 在域名概览页面右侧可以找到 Zone ID，但通常不需要手动配置。

### Q: API 请求失败怎么办？
A: 检查 Token 是否正确，权限是否足够，网络连接是否正常。

### Q: 域名列表为空？
A: 确保账户中有域名，且 Token 有 `Zone:Read` 权限。

## 🚀 快速开始

1. **获取 API Token**：按照上述步骤创建 Custom Token
2. **配置 SSLcat**：在配置文件中设置 Token
3. **启用提供商**：设置 `"enabled": true`
4. **重启服务**：重启 SSLcat 使配置生效
5. **测试连接**：运行测试脚本验证配置

## 📝 配置示例

完整的 Cloudflare DNS 配置示例：

```json
{
  "ssl": {
    "dns_providers": [
      {
        "name": "cloudflare-dns",
        "type": "cloudflare",
        "enabled": true,
        "api_key": "your_cloudflare_api_token_here",
        "api_secret": "",
        "zone_id": "",
        "priority": 3
      }
    ],
    "default_dns_provider": "cloudflare-dns"
  }
}
```

配置完成后，Cloudflare 的域名个数就不会再显示为 0 了！
