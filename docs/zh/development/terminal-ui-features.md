# Terminal UI 功能对比与规划

## Web 界面功能清单

### 核心功能模块

1. **Dashboard（仪表盘）**
   - 系统统计信息
   - 活跃代理规则数
   - SSL 证书数量
   - 系统运行时间
   - 快速操作入口

2. **Proxy Management（代理管理）**
   - 代理规则列表
   - 添加/编辑代理规则
   - 删除代理规则
   - 高级功能：
     - 负载均衡配置
     - 健康检查配置
     - 路径前缀规则
     - 会话保持
     - 故障转移
     - 自定义请求头
     - CDN 模式配置
     - HTTP Host 头部优化设置

3. **Sites Management（站点管理）**
   - 静态站点管理（添加/编辑/删除）
   - PHP 站点管理（添加/编辑/删除）
   - Git 部署应用管理

4. **SSL Management（SSL 证书管理）**
   - 证书列表
   - 证书申请
   - 证书续期
   - 证书上传/下载
   - 证书删除
   - DNS 验证配置
   - ACME 证书同步

5. **DNS Management（DNS 管理）**
   - DNS 提供商配置（Cloudflare、Aliyun、Tencent、AWS 等）
   - DNS 提供商添加/编辑/删除
   - DNS 验证测试
   - DNS 请求证书

6. **Security（安全设置）**
   - WAF 配置
   - DDoS 防护配置
   - IP 封禁管理
   - 封禁 IP 列表查看/解封
   - TLS 指纹追踪
   - 安全日志查看
   - 威胁情报配置

7. **Settings（系统设置）**
   - 基础设置（端口模式、HTTPS 等）
   - SSL 设置（邮箱、自动续期等）
   - 日志设置（访问日志、日志级别等）
   - 压缩设置
   - 上游缓存设置
   - 通知设置（邮件、Webhook 等）

8. **CDN Cache（CDN 缓存管理）**
   - 缓存统计
   - 缓存清理
   - 缓存配置

9. **Statistics（访问统计）**
   - 访问统计图表
   - 请求统计
   - 流量统计

10. **Slow Requests（慢请求分析）**
    - 慢请求列表
    - 慢请求分析

11. **Notifications（通知管理）**
    - 通知渠道配置
    - 通知历史查看

12. **Git Server（Git 服务器管理）**
    - Git 应用列表
    - Git 应用添加/编辑/删除
    - SSH 密钥管理
    - Git 服务器配置

13. **Cluster（集群管理）**
    - 集群模式配置
    - 主节点配置
    - 同步配置
    - 集群状态查看

14. **AI Security Analysis（AI 安全分析）**
    - AI 安全扫描
    - 安全建议
    - 自动修复

15. **Image Optimization（图片优化）**
    - 图片优化配置
    - WebP 转换配置

16. **User Management（用户管理）**
    - 用户列表
    - 用户添加/编辑/删除
    - 修改密码

## Terminal UI 当前实现状态

### ✅ 已实现
- [x] 基础菜单导航
- [x] 配置管理（基础浏览和编辑）
- [x] 状态监控（系统信息、配置信息、统计）
- [x] 代理规则管理（基础 CRUD）
- [x] 代理规则高级配置（多步骤向导）
  - [x] 基础配置（域名、启用、SSL Only）
  - [x] 后端服务器管理（完整 CRUD）
  - [x] 负载均衡配置（算法选择）
  - [x] 健康检查配置（路径、间隔、超时、方法、状态码）
  - [x] 会话保持配置（方法、Cookie、TTL）
  - [x] 故障转移配置（重试次数、间隔、阈值）
  - [x] 高级选项（HTTP Host 头部优化、CDN、WebSocket 优化开关）
  - [x] 路径前缀规则管理（完整 CRUD）
  - [x] 自定义头部管理（请求头/响应头 CRUD）
- [x] SSL 证书管理（列表和详情查看）

### ❌ 缺失功能

#### 高优先级（核心功能）
1. **访问控制配置**
   - [ ] Basic Auth 启用 (auth_enabled)
   - [ ] Basic Auth 用户列表 (auth_users)
   - [ ] 会话超时 (auth_session_timeout)
   - [ ] Cookie 域名 (auth_cookie_domain)

2. **简单路径前缀配置**
   - [ ] 路径前缀列表 (path_prefixes)
   - [ ] 精确匹配开关 (path_exact)

3. **代理超时配置**
   - [ ] 连接超时 (connect_timeout_sec)
   - [ ] 连接保持超时 (keep_alive_timeout_sec)
   - [ ] 空闲连接超时 (idle_timeout_sec)
   - [ ] TLS 握手超时 (tls_handshake_timeout_sec)
   - [ ] Expect-Continue 超时 (expect_continue_timeout_sec)
   - [ ] 健康检查超时 (health_check_timeout_sec)

4. **代理规则高级配置**
   - [x] 负载均衡配置 ✅
   - [x] 健康检查配置 ✅
   - [x] 路径前缀规则 ✅
   - [x] 会话保持配置 ✅
   - [x] 故障转移配置 ✅
   - [x] 自定义请求头 ✅
   - [x] CDN 模式配置 ✅

2. **站点管理**
   - [ ] 静态站点管理
   - [ ] PHP 站点管理
   - [ ] Git 部署应用管理

3. **DNS 管理**
   - [ ] DNS 提供商管理
   - [ ] DNS 验证测试
   - [ ] DNS 请求证书

4. **安全设置**
   - [ ] WAF 配置
   - [ ] DDoS 防护配置
   - [ ] IP 封禁管理（查看/解封）
   - [ ] 安全日志查看
   - [ ] TLS 指纹查看

5. **SSL 证书高级功能**
   - [ ] 证书申请（交互式）
   - [ ] 证书续期
   - [ ] 证书上传/下载
   - [ ] ACME 证书同步

#### 中优先级（增强功能）
5. **WebSocket 详细配置**
   - [ ] WebSocket 缓冲区大小 (websocket_buffer_size)
   - [ ] WebSocket 读取超时 (websocket_read_timeout)
   - [ ] WebSocket 写入超时 (websocket_write_timeout)
   - [ ] WebSocket 心跳间隔 (websocket_ping_interval)
   - [ ] WebSocket 连接超时 (websocket_timeout)

6. **性能监控配置**
   - [ ] 请求追踪 (enable_tracing)
   - [ ] 指标收集 (enable_metrics)
   - [ ] 基础设置（端口模式等）
   - [ ] SSL 设置
   - [ ] 日志设置
   - [ ] 压缩设置
   - [ ] 上游缓存设置

7. **CDN 缓存管理**
   - [ ] 缓存统计
   - [ ] 缓存清理

8. **通知管理**
   - [ ] 通知渠道配置
   - [ ] 通知历史查看

9. **集群管理**
   - [ ] 集群配置
   - [ ] 集群状态查看

#### 低优先级（辅助功能）
10. **访问统计**
    - [ ] 统计信息查看（从日志文件读取）

11. **慢请求分析**
    - [ ] 慢请求列表（从日志文件读取）

12. **用户管理**
    - [ ] 用户列表
    - [ ] 用户管理

13. **AI 安全分析**
    - [ ] AI 安全扫描触发
    - [ ] 安全建议查看

14. **图片优化**
    - [ ] 图片优化配置

## Terminal UI 超越 Web 端的优势

### 1. 命令行友好
- ✅ 支持脚本化操作
- ✅ 支持管道和重定向
- ✅ 支持配置文件路径参数

### 2. 无需网络
- ✅ 直接操作配置文件，无需服务运行
- ✅ 离线编辑配置
- ✅ SSH 环境下的完整功能

### 3. 快速操作
- ✅ 键盘快捷键导航
- ✅ 批量操作支持
- ✅ 快速搜索和过滤

### 4. 终端特性
- ✅ 支持终端颜色和样式
- ✅ 支持窄终端显示
- ✅ 支持远程终端访问

### 5. 扩展功能（可添加）
- [ ] 配置验证和修复建议
- [ ] 配置差异对比
- [ ] 配置备份和恢复
- [ ] 批量导入/导出
- [ ] 配置模板
- [ ] 实时日志查看（tail）
- [ ] 性能监控（基于配置文件）

