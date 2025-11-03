# Terminal UI 功能对比与实现状态

## 代理规则配置功能对比

### Web 端功能清单

#### 基础配置
- [x] 域名 (domain)
- [x] 启用状态 (enabled)
- [x] SSL Only (ssl_only)

#### 后端配置
- [x] 后端服务器列表 (backends)
- [x] 后端权重、优先级
- [x] 后端健康检查配置

#### 负载均衡
- [x] 负载均衡算法 (load_balancer_algorithm)
- [x] 会话保持 (session_affinity)

#### 健康检查
- [x] 启用状态 (health_check_enabled)
- [x] 检查路径 (health_check_path)
- [x] 检查间隔 (health_check_interval)
- [x] 超时时间 (health_check_timeout)
- [x] HTTP 方法 (health_check_method)
- [x] 期望状态码 (expected_status_code)

#### 故障转移
- [x] 启用状态 (failover_enabled)
- [x] 最大重试次数 (max_retries)
- [x] 重试间隔 (retry_interval)
- [x] 故障阈值 (failure_threshold)
- [x] 恢复阈值 (recovery_threshold)

#### 路径前缀
- [ ] 简单路径前缀 (path_prefixes, path_exact) - **缺失**
- [x] 路径前缀规则 (path_prefix_rules) - **已实现**

#### 高级选项
- [x] HTTP Host 头部优化 (optimize_host_header)
- [x] CDN 模式 (cdn_enabled, cdn_preset, cdn_ttl_seconds)
- [x] WebSocket 优化开关 (websocket_optimized)
- [ ] WebSocket 详细配置 - **部分缺失**
  - [ ] WebSocket 缓冲区大小 (websocket_buffer_size)
  - [ ] WebSocket 读取超时 (websocket_read_timeout)
  - [ ] WebSocket 写入超时 (websocket_write_timeout)
  - [ ] WebSocket 心跳间隔 (websocket_ping_interval)
  - [ ] WebSocket 连接超时 (websocket_timeout)

#### 访问控制
- [ ] Basic Auth 启用 (auth_enabled) - **缺失**
- [ ] Basic Auth 用户列表 (auth_users) - **缺失**
- [ ] 会话超时 (auth_session_timeout) - **缺失**
- [ ] Cookie 域名 (auth_cookie_domain) - **缺失**

#### 代理超时配置
- [ ] 连接超时 (connect_timeout_sec) - **缺失**
- [ ] 连接保持超时 (keep_alive_timeout_sec) - **缺失**
- [ ] 空闲连接超时 (idle_timeout_sec) - **缺失**
- [ ] TLS 握手超时 (tls_handshake_timeout_sec) - **缺失**
- [ ] Expect-Continue 超时 (expect_continue_timeout_sec) - **缺失**
- [ ] 健康检查超时 (health_check_timeout_sec) - **缺失**

#### 自定义头部
- [x] 请求头 (upstream_request_headers) - **已实现**
- [x] 响应头 (response_headers) - **已实现**

#### 性能监控
- [ ] 请求追踪 (enable_tracing) - **缺失**
- [ ] 指标收集 (enable_metrics) - **缺失**

#### CORS 配置
- [ ] CORS 预设配置 - **缺失**

## Terminal UI 特有功能

- [x] 多步骤配置向导
- [x] 模块化组件管理
- [x] 实时配置验证
- [x] 快捷键操作

## 待实现功能优先级

### 高优先级（核心功能）
1. **访问控制配置** - Basic Auth 管理
2. **简单路径前缀配置** - 补充路径前缀规则
3. **代理超时配置** - 完整的超时设置

### 中优先级（增强功能）
4. **WebSocket 详细配置** - 完整参数设置
5. **性能监控配置** - 追踪和指标

### 低优先级（可选功能）
6. **CORS 配置** - 如果 web 端有实现
