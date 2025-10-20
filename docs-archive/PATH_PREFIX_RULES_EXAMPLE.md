# 多组路径前缀规则配置示例

## 新的数据结构设计

### PathPrefixRule 结构
```go
type PathPrefixRule struct {
    // 路径前缀配置
    Prefixes []string `json:"prefixes"` // 路径前缀列表
    Exact    bool     `json:"exact"`    // 是否精确匹配
    
    // 后端服务器配置
    Backends []ProxyBackend `json:"backends"` // 该规则对应的后端服务器列表
    
    // 负载均衡配置
    LoadBalancerAlgorithm string `json:"load_balancer_algorithm"`
    
    // 会话保持配置
    SessionAffinityEnabled bool   `json:"session_affinity_enabled"`
    SessionAffinityMethod  string `json:"session_affinity_method"`
    SessionAffinityCookie  string `json:"session_affinity_cookie"`
    SessionAffinityHeader  string `json:"session_affinity_header"`
    SessionAffinityTTL     int    `json:"session_affinity_ttl"`
    
    // 健康检查配置
    HealthCheckEnabled  bool   `json:"health_check_enabled"`
    HealthCheckPath     string `json:"health_check_path"`
    HealthCheckInterval int    `json:"health_check_interval"`
    HealthCheckTimeout  int    `json:"health_check_timeout"`
    HealthCheckMethod   string `json:"health_check_method"`
    ExpectedStatusCode  int    `json:"expected_status_code"`
    
    // 故障转移配置
    FailoverEnabled   bool `json:"failover_enabled"`
    MaxRetries        int  `json:"max_retries"`
    RetryInterval     int  `json:"retry_interval"`
    FailureThreshold  int  `json:"failure_threshold"`
    RecoveryThreshold int  `json:"recovery_threshold"`
    
    // 规则元数据
    Name        string `json:"name,omitempty"`
    Description string `json:"description,omitempty"`
    Enabled     bool   `json:"enabled"`
}
```

## 配置示例

### 1. PHP站点多组路径前缀配置

```json
{
  "domain": "php.example.com",
  "root": "/var/www/php",
  "fcgi_addr": "127.0.0.1:9000",
  "enabled": true,
  
  "path_prefix_rules": [
    {
      "name": "API v1 规则",
      "description": "API v1 路径前缀规则",
      "enabled": true,
      "prefixes": ["/api/v1/", "/api/v1/users/", "/api/v1/orders/"],
      "exact": false,
      "backends": [
        {
          "id": "api_v1_backend_1",
          "host": "api-v1-server-1.example.com",
          "port": 8080,
          "weight": 2,
          "priority": 1,
          "enabled": true
        },
        {
          "id": "api_v1_backend_2",
          "host": "api-v1-server-2.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 2,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "weighted_round_robin",
      "session_affinity_enabled": true,
      "session_affinity_method": "cookie",
      "session_affinity_cookie": "API_V1_SESSION",
      "health_check_enabled": true,
      "health_check_path": "/api/v1/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    },
    {
      "name": "API v2 规则",
      "description": "API v2 路径前缀规则",
      "enabled": true,
      "prefixes": ["/api/v2/", "/api/v2/users/", "/api/v2/orders/"],
      "exact": false,
      "backends": [
        {
          "id": "api_v2_backend_1",
          "host": "api-v2-server-1.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 1,
          "enabled": true
        },
        {
          "id": "api_v2_backend_2",
          "host": "api-v2-server-2.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 2,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "round_robin",
      "session_affinity_enabled": false,
      "health_check_enabled": true,
      "health_check_path": "/api/v2/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    },
    {
      "name": "管理后台规则",
      "description": "管理后台路径前缀规则",
      "enabled": true,
      "prefixes": ["/admin/", "/admin/login", "/admin/dashboard"],
      "exact": false,
      "backends": [
        {
          "id": "admin_backend_1",
          "host": "admin-server-1.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 1,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "round_robin",
      "session_affinity_enabled": true,
      "session_affinity_method": "cookie",
      "session_affinity_cookie": "ADMIN_SESSION",
      "health_check_enabled": true,
      "health_check_path": "/admin/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    }
  ]
}
```

### 2. 静态站点多组路径前缀配置

```json
{
  "domain": "static.example.com",
  "root": "/var/www/html",
  "index": "index.html",
  "enabled": true,
  
  "path_prefix_rules": [
    {
      "name": "API 服务规则",
      "description": "API 服务路径前缀规则",
      "enabled": true,
      "prefixes": ["/api/", "/api/users/", "/api/orders/"],
      "exact": false,
      "backends": [
        {
          "id": "api_backend_1",
          "host": "api-server-1.example.com",
          "port": 8080,
          "weight": 2,
          "priority": 1,
          "enabled": true
        },
        {
          "id": "api_backend_2",
          "host": "api-server-2.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 2,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "weighted_round_robin",
      "session_affinity_enabled": true,
      "session_affinity_method": "ip",
      "health_check_enabled": true,
      "health_check_path": "/api/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    },
    {
      "name": "微服务规则",
      "description": "微服务路径前缀规则",
      "enabled": true,
      "prefixes": ["/microservice/", "/microservice/user/", "/microservice/order/"],
      "exact": false,
      "backends": [
        {
          "id": "microservice_backend_1",
          "host": "microservice-server-1.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 1,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "round_robin",
      "session_affinity_enabled": false,
      "health_check_enabled": true,
      "health_check_path": "/microservice/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    }
  ]
}
```

### 3. 代理转发多组路径前缀配置

```json
{
  "domain": "proxy.example.com",
  "enabled": true,
  "ssl_only": true,
  
  "path_prefix_rules": [
    {
      "name": "用户服务规则",
      "description": "用户服务路径前缀规则",
      "enabled": true,
      "prefixes": ["/user/", "/user/profile/", "/user/settings/"],
      "exact": false,
      "backends": [
        {
          "id": "user_service_1",
          "host": "user-service-1.example.com",
          "port": 8080,
          "weight": 2,
          "priority": 1,
          "enabled": true
        },
        {
          "id": "user_service_2",
          "host": "user-service-2.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 2,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "weighted_round_robin",
      "session_affinity_enabled": true,
      "session_affinity_method": "cookie",
      "session_affinity_cookie": "USER_SESSION",
      "health_check_enabled": true,
      "health_check_path": "/user/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    },
    {
      "name": "订单服务规则",
      "description": "订单服务路径前缀规则",
      "enabled": true,
      "prefixes": ["/order/", "/order/create/", "/order/list/"],
      "exact": false,
      "backends": [
        {
          "id": "order_service_1",
          "host": "order-service-1.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 1,
          "enabled": true
        },
        {
          "id": "order_service_2",
          "host": "order-service-2.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 2,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "round_robin",
      "session_affinity_enabled": false,
      "health_check_enabled": true,
      "health_check_path": "/order/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    },
    {
      "name": "支付服务规则",
      "description": "支付服务路径前缀规则",
      "enabled": true,
      "prefixes": ["/payment/", "/payment/process/", "/payment/callback/"],
      "exact": false,
      "backends": [
        {
          "id": "payment_service_1",
          "host": "payment-service-1.example.com",
          "port": 8080,
          "weight": 1,
          "priority": 1,
          "enabled": true
        }
      ],
      "load_balancer_algorithm": "round_robin",
      "session_affinity_enabled": false,
      "health_check_enabled": true,
      "health_check_path": "/payment/health",
      "health_check_interval": 30,
      "health_check_timeout": 5,
      "health_check_method": "GET",
      "expected_status_code": 200
    }
  ]
}
```

## 处理流程

### 请求处理逻辑

1. **请求到达** → 检查域名匹配
2. **遍历路径前缀规则** → 按顺序检查每个规则
3. **找到匹配的规则** → 使用该规则的后端服务器配置
4. **执行负载均衡** → 根据规则配置选择后端服务器
5. **转发请求** → 到选中的后端服务器

### 规则优先级

- 规则按配置顺序检查
- 第一个匹配的规则生效
- 可以配置规则的启用/禁用状态
- 支持规则的名称和描述

## 优势

### 1. 灵活性
- 支持多组路径前缀配置
- 每组可以有不同的后端服务器
- 每组可以有不同的负载均衡策略

### 2. 可维护性
- 规则有名称和描述
- 可以单独启用/禁用规则
- 配置结构清晰

### 3. 可扩展性
- 支持微服务架构
- 支持版本管理
- 支持不同的服务策略

## 使用场景

### 1. 微服务架构
- 用户服务：`/user/` → user-service
- 订单服务：`/order/` → order-service
- 支付服务：`/payment/` → payment-service

### 2. API版本管理
- API v1：`/api/v1/` → legacy-api-server
- API v2：`/api/v2/` → new-api-server
- API v3：`/api/v3/` → latest-api-server

### 3. 功能模块分离
- 管理后台：`/admin/` → admin-server
- 用户前台：`/user/` → user-server
- 数据统计：`/stats/` → stats-server
