# 代理规则统一后端迁移计划

## 📋 迁移概述

### 目标
将现有的"转发规则"和"负载均衡配置"统一为"代理规则"概念，所有规则都使用统一的后端数组配置。

### 迁移策略
- **静默升级**：读取时兼容旧配置，保存时使用新格式
- **向后兼容**：保留旧字段，确保现有配置正常工作
- **渐进式清理**：未来版本中逐步移除兼容字段

## 🔄 配置结构变化

### 旧结构（兼容保留）
```json
{
  "domain": "app.example.com",
  "target": "192.168.1.10",           // 旧字段：单后端目标
  "port": 8080,                       // 旧字段：单后端端口
  "load_balancer_enabled": true,      // 旧字段：负载均衡开关
  "load_balancer_algorithm": "round_robin",  // 旧字段：负载均衡算法
  "load_balancer_backends": [...]     // 旧字段：负载均衡后端列表
}
```

### 新结构（统一格式）
```json
{
  "domain": "app.example.com",
  "backends": [                       // 新字段：统一后端列表
    {
      "id": "app.example.com_backend_1",
      "host": "192.168.1.10",
      "port": 8080,
      "weight": 1,
      "enabled": true
    }
  ],
  "load_balancing": {                 // 新字段：负载均衡配置
    "algorithm": "round_robin",
    "session_affinity": {
      "enabled": false,
      "method": "cookie",
      "cookie_name": "JSESSIONID",
      "ttl": 3600
    }
  }
}
```

## 🚀 实施阶段

### 阶段1：兼容性实现（当前版本）
- [x] 添加新的配置字段
- [x] 实现读取时的兼容性迁移
- [x] 实现保存时的静默升级
- [x] 更新前端界面支持新格式
- [x] 保留旧字段以确保兼容性

### 阶段2：文档更新（当前版本）
- [x] 更新配置文档
- [x] 更新API文档
- [x] 更新前端界面说明
- [x] 添加迁移指南

### 阶段3：清理计划（未来版本 v1.4.0+）
- [ ] 标记旧字段为废弃（deprecated）
- [ ] 添加废弃警告日志
- [ ] 提供迁移工具
- [ ] 在配置验证中警告旧字段使用

### 阶段4：完全移除（未来版本 v1.5.0+）
- [ ] 移除旧字段支持
- [ ] 清理兼容性代码
- [ ] 更新所有示例配置
- [ ] 强制要求新格式

## 📝 兼容性处理逻辑

### 读取配置时
```go
func (rule *ProxyRule) MigrateToUnifiedBackends() {
    // 如果已经有新的 backends 字段，直接返回
    if len(rule.Backends) > 0 {
        return
    }
    
    // 迁移逻辑：从旧字段到新字段
    if rule.LoadBalancerEnabled && len(rule.LoadBalancerBackends) > 0 {
        // 从负载均衡配置迁移
        rule.Backends = rule.LoadBalancerBackends
    } else if rule.Target != "" {
        // 从单后端配置迁移
        rule.Backends = []ProxyBackend{
            {
                ID:      fmt.Sprintf("%s_backend_1", rule.Domain),
                Host:    rule.Target,
                Port:    rule.Port,
                Weight:  1,
                Enabled: true,
            },
        }
    }
}
```

### 保存配置时
```go
func (rule *ProxyRule) PrepareForSave() {
    // 确保 backends 字段有值
    if len(rule.Backends) == 0 {
        rule.MigrateToUnifiedBackends()
    }
    
    // 根据 backends 数量设置负载均衡状态
    if len(rule.Backends) > 1 {
        rule.LoadBalancerEnabled = true
        if rule.LoadBalancerAlgorithm == "" {
            rule.LoadBalancerAlgorithm = "round_robin"
        }
    } else {
        rule.LoadBalancerEnabled = false
    }
}
```

## 🎯 前端界面变化

### 统一界面设计
- **所有规则**：显示"后端服务器列表"
- **单后端**：显示1个服务器 + "添加服务器"按钮
- **多后端**：显示多个服务器 + 负载均衡选项
- **智能提示**：根据后端数量显示不同状态

### 状态标识
```
🟢 app.example.com → 1个后端服务器
🔵 api.example.com → 3个后端服务器 (负载均衡)
🔵 cdn.example.com → 5个后端服务器 (负载均衡)
```

## 📊 迁移统计

### 配置类型分布
- **单后端规则**：从 `target` + `port` 迁移到 `backends[0]`
- **负载均衡规则**：从 `load_balancer_backends` 迁移到 `backends`
- **新规则**：直接使用 `backends` 字段

### 兼容性保证
- ✅ 旧配置文件直接可用
- ✅ 旧API调用正常工作
- ✅ 前端界面自动适配
- ✅ 配置保存时自动升级

## 🔧 技术实现要点

### 后端配置结构
```go
type ProxyRule struct {
    // 基础字段
    Domain  string `json:"domain"`
    Enabled bool   `json:"enabled"`
    SSLOnly bool   `json:"ssl_only"`
    
    // 新字段：统一后端配置
    Backends []ProxyBackend `json:"backends,omitempty"`
    
    // 保留字段：向后兼容
    Target  string `json:"target,omitempty"`  // 废弃
    Port    int    `json:"port,omitempty"`    // 废弃
    
    // 保留字段：负载均衡兼容
    LoadBalancerEnabled   bool           `json:"load_balancer_enabled,omitempty"`   // 废弃
    LoadBalancerAlgorithm string         `json:"load_balancer_algorithm,omitempty"` // 废弃
    LoadBalancerBackends  []ProxyBackend `json:"load_balancer_backends,omitempty"`  // 废弃
    
    // 其他配置保持不变...
}
```

### 前端类型定义
```typescript
interface ProxyRuleForm {
  domain: string
  enabled: boolean
  ssl_only: boolean
  
  // 新字段：统一后端配置
  backends: ProxyBackend[]
  
  // 保留字段：兼容性
  target?: string
  port?: number
  load_balancer_enabled?: boolean
  load_balancer_algorithm?: string
  load_balancer_backends?: ProxyBackend[]
  
  // 其他配置...
}
```

## 📅 时间线

- **v1.3.x**：实现兼容性支持，静默升级
- **v1.4.x**：标记旧字段为废弃，添加警告
- **v1.5.x**：完全移除旧字段支持

## 🎉 预期效果

### 用户体验
- ✅ 配置概念更清晰
- ✅ 界面操作更统一
- ✅ 功能更强大（自动负载均衡）
- ✅ 向后兼容无感知

### 开发体验
- ✅ 代码逻辑更统一
- ✅ 配置处理更简单
- ✅ 功能扩展更容易
- ✅ 维护成本更低

---

**注意**：此迁移计划确保完全向后兼容，用户无需手动迁移配置。所有升级都是静默进行的。
