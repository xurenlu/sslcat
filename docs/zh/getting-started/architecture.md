# SSLcat 架构概述

本文档提供了 SSLcat 架构、组件以及它们如何协同工作以提供 SSL 代理功能的全面概述。

## 🏗️ 系统架构

### 高级架构

```mermaid
graph TB
    subgraph "客户端层"
        A[Web 客户端<br/>浏览器]
        B[API 客户端<br/>REST/WebSocket]
        C[代理客户端<br/>HTTPS/HTTP]
    end
    
    subgraph "SSLcat 核心引擎"
        D[请求路由器<br/>• 域名解析<br/>• 路径匹配<br/>• 规则评估]
        E[SSL 管理器<br/>• 证书管理<br/>• Let's Encrypt 集成<br/>• 自动续期]
        F[代理引擎<br/>• HTTP/HTTPS 转发<br/>• WebSocket 支持<br/>• 负载均衡]
        G[安全层<br/>• IP 阻止<br/>• 速率限制<br/>• 访问控制]
    end
    
    subgraph "管理界面"
        H[Web 管理界面<br/>• 仪表板<br/>• 配置管理<br/>• 监控和日志<br/>• 用户管理]
    end
    
    subgraph "后端服务"
        I[Web 应用<br/>端口 8080]
        J[API 服务<br/>端口 3000]
        K[其他服务<br/>端口 5000]
    end
    
    A --> D
    B --> D
    C --> D
    D --> E
    D --> F
    D --> G
    F --> I
    F --> J
    F --> K
    H --> D
```

## 🔧 核心组件

### 1. 请求路由器
请求路由器是所有传入请求的入口点。它处理：

- **域名解析**：确定哪个代理规则适用于请求
- **路径匹配**：将请求路径与配置的规则匹配
- **规则评估**：应用适当的代理配置
- **协议检测**：识别 HTTP 与 HTTPS 请求

### 2. SSL 管理器
SSL 管理器处理所有证书相关操作：

- **证书获取**：从 Let's Encrypt 请求证书
- **证书存储**：管理证书文件和元数据
- **自动续期**：监控证书过期并自动续期
- **证书验证**：验证证书链和信任

### 3. 代理引擎
代理引擎处理请求的实际转发：

- **HTTP/HTTPS 转发**：将请求转发到后端服务
- **WebSocket 支持**：处理 WebSocket 连接
- **负载均衡**：在多个后端之间分配负载
- **健康检查**：监控后端服务健康

### 4. 安全层
安全层提供保护和访问控制：

- **IP 阻止**：阻止恶意 IP 地址
- **速率限制**：防止滥用和 DoS 攻击
- **访问控制**：管理用户权限和认证
- **审计日志**：记录安全事件和访问尝试

## 🔄 请求流程

### 请求处理流程图

```mermaid
sequenceDiagram
    participant C as 客户端
    participant S as SSLcat 服务器
    participant SSL as SSL 管理器
    participant R as 请求路由器
    participant P as 代理引擎
    participant B as 后端服务
    
    C->>S: HTTPS 请求 (端口 443)
    S->>SSL: SSL 证书验证
    SSL-->>S: 证书有效
    S->>S: 解密请求
    S->>R: 转发请求
    R->>R: 域名解析
    R->>R: 规则匹配
    R->>P: 代理规则
    P->>B: 转发到后端
    B-->>P: 后端响应
    P-->>S: 代理响应
    S->>S: SSL 加密
    S-->>C: HTTPS 响应
```

### 详细步骤说明

1. **传入请求**
   ```bash
   # 客户端发起 HTTPS 请求
   curl -I https://example.com
   ```

2. **SSL 终止**
   ```yaml
   # SSL 配置示例
   ssl:
     certificates:
       - domain: "example.com"
         provider: "letsencrypt"
         email: "admin@example.com"
         auto_renew: true
   ```

3. **域名解析**
   ```go
   // 域名解析逻辑
   func resolveDomain(host string) (*ProxyRule, error) {
       for _, rule := range config.ProxyRules {
           if rule.Domain == host {
               return &rule, nil
           }
       }
       return nil, errors.New("domain not found")
   }
   ```

4. **后端转发**
   ```yaml
   # 代理规则配置
   proxy:
     rules:
       - domain: "example.com"
         target: "http://localhost:8080"
         ssl: true
         load_balancing: "round_robin"
   ```

5. **响应交付**
   ```go
   // 响应处理
   func handleResponse(w http.ResponseWriter, resp *http.Response) {
       // 复制响应头
       for key, values := range resp.Header {
           for _, value := range values {
               w.Header().Add(key, value)
           }
       }
       // 复制响应体
       io.Copy(w, resp.Body)
   }
   ```

## 📊 数据流架构

### 配置管理流程

```mermaid
graph LR
    A[Web 界面] --> B[配置解析器]
    B --> C[规则引擎]
    B --> D[配置存储]
    C --> E[运行时状态]
    
    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff3e0
    style E fill:#fce4ec
```

### 证书管理流程

```mermaid
graph TB
    A[Let's Encrypt API] --> B[SSL 管理器]
    B --> C[证书存储]
    B --> D[自动续期调度器]
    C --> E[证书缓存]
    
    subgraph "证书生命周期"
        F[证书申请] --> G[证书验证]
        G --> H[证书安装]
        H --> I[证书监控]
        I --> J[证书续期]
        J --> F
    end
    
    B --> F
    
    style A fill:#e3f2fd
    style B fill:#f1f8e9
    style C fill:#fff8e1
    style D fill:#fce4ec
    style E fill:#e8f5e8
```

## 🗄️ 存储架构

### 配置存储
- **主配置**：`/etc/sslcat/sslcat.conf` (JSON 格式)
- **备份配置**：`/opt/sslcat/backup/sslcat.conf.backup`
- **运行时配置**：内存中的配置缓存

### 证书存储
- **证书文件**：`/opt/sslcat/certs/domain.crt`
- **私钥**：`/opt/sslcat/keys/domain.key`
- **证书元数据**：`/opt/sslcat/data/certificates.json`

### 日志存储
- **访问日志**：`/opt/sslcat/logs/access.log`
- **错误日志**：`/opt/sslcat/logs/error.log`
- **安全日志**：`/opt/sslcat/logs/security.log`

### 数据存储
- **用户数据**：`/opt/sslcat/data/users.json`
- **会话数据**：`/opt/sslcat/data/sessions.json`
- **统计信息**：`/opt/sslcat/data/statistics.json`

## 🔐 安全架构

### 认证流程
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   用户登录      │───▶│  认证管理器     │───▶│  会话存储       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  令牌管理器     │    │   权限验证器    │
                       │                 │    │                 │
                       └─────────────────┘    └─────────────────┘
```

### 安全层
1. **网络安全**：TLS 加密、证书验证
2. **应用安全**：输入验证、输出编码
3. **访问控制**：基于角色的权限、API 认证
4. **审计安全**：全面日志记录、安全监控

## 🚀 性能架构

### 连接池
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  客户端请求     │───▶│   连接池        │───▶│   后端服务      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 缓存策略
- **证书缓存**：内存中的证书存储
- **配置缓存**：运行时配置缓存
- **响应缓存**：静态内容缓存
- **DNS 缓存**：域名解析缓存

### 负载均衡
- **轮询**：均匀分配请求
- **健康检查**：监控后端可用性
- **故障转移**：自动后端切换
- **加权分配**：自定义后端优先级

## 🔧 配置架构

### 配置层次结构
1. **命令行**：最高优先级
2. **环境变量**：第二优先级
3. **配置文件**：默认设置
4. **内置默认值**：回退值

### 配置验证
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  配置输入       │───▶│  模式验证器     │───▶│  验证的配置     │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📈 监控架构

### 指标收集
- **系统指标**：CPU、内存、磁盘使用
- **应用指标**：请求率、响应时间
- **安全指标**：登录失败、被阻止的 IP
- **证书指标**：过期日期、续期状态

### 日志架构
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   应用程序      │───▶│   日志管理器    │───▶│   日志存储      │
│     事件        │    │                 │    │   (文件/数据库) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔄 部署架构

### 单实例
```
┌─────────────────┐
│   SSLcat        │
│   (单机)        │
└─────────────────┘
```

### 高可用性
```
┌─────────────────┐    ┌─────────────────┐
│   SSLcat A      │    │   SSLcat B      │
│   (主)          │    │   (备)          │
└─────────────────┘    └─────────────────┘
```

### 负载均衡
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   负载均衡器    │───▶│   SSLcat A      │    │   SSLcat B      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🛠️ 开发架构

### 代码组织
```
sslcat/
├── main.go                 # 应用程序入口点
├── internal/              # 内部包
│   ├── config/           # 配置管理
│   ├── ssl/              # SSL 证书处理
│   ├── proxy/            # 代理功能
│   ├── security/         # 安全功能
│   ├── web/              # Web 界面
│   └── graceful/         # 优雅重启
├── web/                  # Web 资源
│   ├── templates/        # HTML 模板
│   └── static/           # 静态文件
└── scripts/              # 实用脚本
```

### API 架构
- **REST API**：基于 HTTP 的配置 API
- **WebSocket API**：实时通信
- **内部 API**：组件间通信
- **外部 API**：第三方集成

## 🔍 故障排除架构

### 错误处理
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   错误检测      │───▶│   错误分类      │───▶│   错误响应      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 健康监控
- **服务健康**：进程状态、资源使用
- **网络健康**：连接性、延迟
- **证书健康**：有效性、过期
- **后端健康**：服务可用性、响应时间

---

*此架构为 SSLcat 的功能提供了坚实的基础。有关实现细节，请参阅[开发指南](../development/setup.md)。*
