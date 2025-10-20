# SSLcat API 文档

## 认证方式

SSLcat 支持两种 API 认证方式：

### 1. Cookie 认证（Web 面板用户）
通过 Web 面板登录后，具有完整的读写权限。

### 2. Bearer Token 认证
在请求头中添加：
```
Authorization: Bearer <your_token>
```

Token 权限：
- `read`: 只读权限，可访问所有 GET 接口
- `write`: 读写权限，可访问所有接口

## API 端点

### 统计信息
```bash
# 获取系统统计
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/stats
```

### 代理规则
```bash
# 获取代理规则列表
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/proxy-rules
```

### SSL 证书
```bash
# 获取证书列表
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/ssl-certs
```

### 安全日志
```bash
# 获取安全访问日志（最近100条）
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/security-logs

# 只获取失败的访问记录
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/security-logs?only_failed=1

# 限制返回条数
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/security-logs?limit=50
```

### 审计日志
```bash
# 获取审计日志
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/audit

# 下载审计日志文件
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/audit?download=1 \
     -o audit-$(date +%Y%m%d).json
```

### TLS 指纹统计
```bash
# 获取 TLS 客户端指纹统计
curl -H "Authorization: Bearer <token>" \
     https://your-domain/sslcat-panel/api/tls-fingerprints
```

## Token 管理

### 生成 Token
通过 Web 面板：`管理面板 → Token 管理 → 生成Token`

### 权限说明
- **只读权限 (read)**：可以访问所有查询类 API，不能进行数据修改
- **读写权限 (write)**：拥有完整的 API 访问权限

## 响应格式

所有 API 响应均为 JSON 格式：

### 成功响应
```json
{
  "data": { ... },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### 错误响应
```json
{
  "error": "error_message",
  "code": "error_code"
}
```

## 状态码

- `200`: 成功
- `401`: 未授权（Token 无效或缺失）
- `403`: 禁止访问（权限不足）
- `404`: 资源不存在
- `500`: 服务器内部错误

## 使用示例

### Python 示例
```python
import requests

# 配置
BASE_URL = "https://your-domain/sslcat-panel/api"
TOKEN = "your_api_token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# 获取统计信息
response = requests.get(f"{BASE_URL}/stats", headers=HEADERS)
stats = response.json()
print(f"活跃规则数: {stats['ActiveRules']}")
print(f"SSL证书数: {stats['SSLCertificates']}")

# 获取代理规则
response = requests.get(f"{BASE_URL}/proxy-rules", headers=HEADERS)
rules = response.json()
for rule in rules:
    print(f"域名: {rule['domain']} -> {rule['target']}")
```

### JavaScript 示例
```javascript
const BASE_URL = 'https://your-domain/sslcat-panel/api';
const TOKEN = 'your_api_token';
const headers = { 'Authorization': `Bearer ${TOKEN}` };

// 获取统计信息
fetch(`${BASE_URL}/stats`, { headers })
  .then(response => response.json())
  .then(data => {
    console.log('系统统计:', data);
  });

// 获取 TLS 指纹统计
fetch(`${BASE_URL}/tls-fingerprints`, { headers })
  .then(response => response.json())
  .then(data => {
    console.log('TLS 指纹统计:', data.fingerprints);
  });
```

## 注意事项

1. **Token 安全**：请妥善保管您的 API Token，避免泄露
2. **权限控制**：根据实际需要选择合适的 Token 权限
3. **速率限制**：API 请求受到安全防护机制限制，避免过于频繁的请求
4. **HTTPS 访问**：建议通过 HTTPS 访问 API 以确保安全性
