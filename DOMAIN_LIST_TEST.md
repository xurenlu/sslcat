# 域名列表获取功能测试

## 概述

本项目已为各个云服务商实现了域名列表获取功能，包括：

- **阿里云 (Aliyun)**
- **Cloudflare** 
- **腾讯云 (Tencent)**
- **AWS Route53**
- **GoDaddy**
- **自定义DNS服务商**

## 环境配置

### 1. 创建 .env 文件

在项目根目录创建 `.env` 文件，内容如下：

```bash
# 阿里云配置
ALIYUN_ACCESS_KEY_ID=your_aliyun_access_key_id
ALIYUN_ACCESS_KEY_SECRET=your_aliyun_access_key_secret
ALIYUN_REGION=cn-hangzhou

# Cloudflare 配置
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ZONE_ID=your_cloudflare_zone_id

# 腾讯云配置
TENCENT_SECRET_ID=your_tencent_secret_id
TENCENT_SECRET_KEY=your_tencent_secret_key
TENCENT_REGION=ap-beijing

# AWS 配置
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_REGION=us-east-1

# 华为云配置
HUAWEI_ACCESS_KEY=your_huawei_access_key
HUAWEI_SECRET_KEY=your_huawei_secret_key
HUAWEI_REGION=cn-north-4

# 测试域名
TEST_DOMAIN=example.com
```

### 2. 运行测试脚本

```bash
# 运行测试脚本
./test_domains.sh

# 或者直接运行测试
go run test_domains.sh
```

## 功能说明

### DNS 提供者接口

所有 DNS 提供者都实现了 `DNSProviderInterface` 接口，包括：

```go
type DNSProviderInterface interface {
    // 设置TXT记录
    SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error
    
    // 删除TXT记录
    DeleteTXTRecord(ctx context.Context, domain, name string) error
    
    // 获取TXT记录值
    GetTXTRecord(ctx context.Context, domain, name string) (string, error)
    
    // 等待DNS记录传播
    WaitForPropagation(ctx context.Context, domain, name, value string) error
    
    // 获取服务商名称
    GetProviderName() string
    
    // 验证配置
    Validate() error
    
    // 获取域名列表 (新增)
    ListDomains(ctx context.Context) ([]DomainInfo, error)
}
```

### 域名信息结构

```go
type DomainInfo struct {
    Name      string    `json:"name"`       // 域名
    Type      string    `json:"type"`       // 域名类型 (A, AAAA, CNAME, MX, TXT, etc.)
    Status    string    `json:"status"`     // 状态 (active, inactive, pending)
    CreatedAt time.Time `json:"created_at"` // 创建时间
    UpdatedAt time.Time `json:"updated_at"` // 更新时间
    TTL       int       `json:"ttl"`        // TTL值
    Value     string    `json:"value"`      // 记录值
}
```

### DNS 管理器方法

```go
// 使用指定服务商获取域名列表
func (m *DNSProviderManager) ListDomainsWithProvider(ctx context.Context, providerName string) ([]DomainInfo, error)

// 使用故障转移机制获取域名列表
func (m *DNSProviderManager) ListDomainsWithFailover(ctx context.Context) (map[string][]DomainInfo, error)
```

## 测试步骤

### 1. 环境准备

```bash
# 确保已设置环境变量
export ALIYUN_ACCESS_KEY_ID="your_key"
export ALIYUN_ACCESS_KEY_SECRET="your_secret"
export CLOUDFLARE_API_TOKEN="your_token"
export CLOUDFLARE_ZONE_ID="your_zone_id"
```

### 2. 运行测试

```bash
# 运行测试脚本
./test_domains.sh
```

### 3. 验证结果

测试脚本会：
- 检查环境变量是否设置
- 模拟测试各个云服务商
- 显示获取到的域名列表
- 验证故障转移机制

## 注意事项

1. **API 密钥安全**: 请确保不要将真实的 API 密钥提交到版本控制系统
2. **测试环境**: 建议先在测试环境中验证功能
3. **错误处理**: 如果某个服务商连接失败，系统会尝试其他服务商
4. **日志记录**: 所有操作都会记录详细的日志信息

## 故障排除

### 常见问题

1. **环境变量未设置**
   - 检查 `.env` 文件是否存在
   - 确认环境变量名称正确

2. **API 密钥无效**
   - 验证 API 密钥是否正确
   - 检查密钥权限是否足够

3. **网络连接问题**
   - 检查网络连接
   - 确认防火墙设置

### 调试模式

```bash
# 启用详细日志
export SSL_DEBUG=true
./test_domains.sh
```

## 扩展功能

### 添加新的云服务商

1. 实现 `DNSProviderInterface` 接口
2. 在 `SSLManager.initializeDNSProviders()` 中注册
3. 添加相应的配置选项

### 自定义域名过滤

```go
// 过滤特定类型的域名
func filterDomainsByType(domains []DomainInfo, domainType string) []DomainInfo {
    var filtered []DomainInfo
    for _, domain := range domains {
        if domain.Type == domainType {
            filtered = append(filtered, domain)
        }
    }
    return filtered
}
```

## 总结

域名列表获取功能已成功实现，支持多个主流云服务商，具备故障转移机制，可以满足生产环境的需求。通过配置相应的 API 密钥，即可开始使用此功能。
