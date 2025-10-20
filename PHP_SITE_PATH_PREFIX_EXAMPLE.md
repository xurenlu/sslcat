# PHP站点路径前缀配置示例

## 完整配置示例

### 场景1：PHP站点 + 负载均衡转发

```json
{
  "domain": "php.example.com",
  "root": "/var/www/php",
  "fcgi_addr": "127.0.0.1:9000",
  "path_prefixes": ["/api/", "/admin/"],
  "path_exact": false,
  
  // 上游服务器配置（用于路径前缀匹配的请求）
  "backends": [
    {
      "id": "api_backend_1",
      "host": "api-server-1.example.com",
      "port": 8080,
      "weight": 1,
      "priority": 0,
      "enabled": true
    },
    {
      "id": "api_backend_2", 
      "host": "api-server-2.example.com",
      "port": 8080,
      "weight": 1,
      "priority": 0,
      "enabled": true
    }
  ],
  
  // 负载均衡配置
  "load_balancer_algorithm": "round_robin",
  "session_affinity_enabled": false,
  
  // 健康检查配置
  "health_check_enabled": true,
  "health_check_path": "/health",
  "health_check_interval": 30,
  "health_check_timeout": 5,
  "health_check_method": "GET",
  "expected_status_code": 200
}
```

### 场景2：混合处理模式

```json
{
  "domain": "mixed.example.com",
  "root": "/var/www/html",
  "fcgi_addr": "127.0.0.1:9000",
  "path_prefixes": ["/api/v1/", "/api/v2/", "/admin/"],
  "path_exact": false,
  
  // 不同路径前缀对应不同的后端服务器
  "backends": [
    {
      "id": "api_v1_backend",
      "host": "api-v1.example.com",
      "port": 8080,
      "weight": 2,
      "priority": 1,
      "enabled": true,
      "metadata": {
        "path_prefix": "/api/v1/"
      }
    },
    {
      "id": "api_v2_backend",
      "host": "api-v2.example.com", 
      "port": 8080,
      "weight": 1,
      "priority": 2,
      "enabled": true,
      "metadata": {
        "path_prefix": "/api/v2/"
      }
    },
    {
      "id": "admin_backend",
      "host": "admin.example.com",
      "port": 8080,
      "weight": 1,
      "priority": 3,
      "enabled": true,
      "metadata": {
        "path_prefix": "/admin/"
      }
    }
  ],
  
  "load_balancer_algorithm": "weighted_round_robin",
  "session_affinity_enabled": true,
  "session_affinity_method": "cookie",
  "session_affinity_cookie": "PHPSESSID"
}
```

## 处理流程

### 请求处理逻辑

1. **请求到达** `php.example.com/api/users`
2. **检查域名匹配** ✅ 匹配
3. **检查路径前缀匹配** ✅ `/api/` 匹配
4. **走负载均衡转发** → 转发到上游API服务器
5. **返回响应**

### 请求处理逻辑（不匹配）

1. **请求到达** `php.example.com/index.php`
2. **检查域名匹配** ✅ 匹配  
3. **检查路径前缀匹配** ❌ 不匹配
4. **走本地PHP处理** → FastCGI处理
5. **返回响应**

## 配置说明

### 路径前缀匹配
- `path_prefixes`: 需要走负载均衡的路径前缀列表
- `path_exact`: 是否精确匹配（false=前缀匹配，true=精确匹配）

### 上游服务器配置
- `backends`: 上游服务器列表
- `load_balancer_algorithm`: 负载均衡算法
- `session_affinity_enabled`: 是否启用会话保持

### 健康检查
- `health_check_enabled`: 是否启用健康检查
- `health_check_path`: 健康检查路径
- `health_check_interval`: 检查间隔（秒）

## 使用场景

### 场景1：API分离
- 静态页面：本地PHP处理
- API请求：转发到专门的API服务器
- 管理页面：转发到管理服务器

### 场景2：微服务架构
- 用户服务：`/api/users/` → user-service
- 订单服务：`/api/orders/` → order-service  
- 支付服务：`/api/payments/` → payment-service
- 其他页面：本地PHP处理

### 场景3：版本管理
- API v1：`/api/v1/` → legacy-api-server
- API v2：`/api/v2/` → new-api-server
- 其他页面：本地PHP处理

## 最佳实践

1. **API路径使用前缀匹配**：`/api/`, `/api/v1/`, `/api/v2/`
2. **管理路径使用精确匹配**：`/admin`
3. **静态资源不配置前缀**：直接本地服务
4. **配置健康检查**：确保上游服务器可用
5. **启用会话保持**：保证用户会话一致性
6. **设置合理的权重**：根据服务器性能分配权重
