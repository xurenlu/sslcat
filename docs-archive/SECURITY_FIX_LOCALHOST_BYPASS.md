# 安全漏洞修复：Localhost 认证绕过

## 修复日期
2025-10-08

## 漏洞等级
🔴 **严重（Critical）**

---

## 漏洞描述

在 SSLcat 的认证系统中发现了一个严重的安全漏洞，攻击者可以通过伪造 HTTP 头部来绕过 localhost 认证检查，获得对管理 API 的未授权访问。

### 漏洞原理

**原始代码逻辑：**

1. `isLocalhostRequest()` 函数通过 `getClientIP()` 获取客户端 IP
2. `getClientIP()` 优先信任 HTTP 头部：`CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For`
3. 如果客户端 IP 是 `127.0.0.1`，则判定为 localhost 请求，**绕过认证**

**攻击场景：**

```bash
# 攻击者从公网 IP 18.181.147.37 发送请求
curl -H "X-Real-IP: 127.0.0.1" \
     http://your-server.com/api/git-server/apps

# 系统判断：
# 1. getClientIP() 从 X-Real-IP 读取到 "127.0.0.1"
# 2. isLocalhostRequest() 返回 true
# 3. 认证被绕过！攻击者无需密码即可访问 API
```

### 受影响的功能

所有使用 `checkAuthWithLocalhostBypass()` 的 API 接口：

- ✅ Git 应用管理 API (`/api/git-server/apps`)
- ✅ SSH 密钥管理 API (`/api/git-server/ssh-key/*`)
- ✅ 部署通知 API (`/api/internal/deploy-notification`)
- ✅ Git 服务器配置 API (`/api/git-server/config`)
- ✅ 所有其他内部管理 API

攻击者可以通过这个漏洞：
- 创建、删除、修改 Git 应用
- 添加、删除 SSH 密钥
- 修改服务器配置
- 触发部署
- 执行其他管理操作

---

## 修复方案

### 核心原则

**永远不要信任 HTTP 头部来判断 localhost！**

HTTP 头部（如 `X-Real-IP`、`X-Forwarded-For`）可以被客户端任意伪造。只有 TCP 连接的 `RemoteAddr` 才是真实可信的。

### 具体修复

#### 1. 修复 `isLocalhostRequest()` 函数

**修改前：**
```go
func (s *Server) isLocalhostRequest(r *http.Request) bool {
    clientIP := s.getClientIP(r)  // ❌ 可以被伪造
    
    if clientIP == "127.0.0.1" || clientIP == "::1" {
        return true
    }
    return false
}
```

**修改后：**
```go
func (s *Server) isLocalhostRequest(r *http.Request) bool {
    // 使用 RemoteAddr 获取真实的 TCP 连接来源
    // 这个值无法通过 HTTP 头部伪造
    remoteAddr := r.RemoteAddr
    if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
        remoteAddr = remoteAddr[:idx]
    }
    
    // 检查是否是 localhost
    if remoteAddr == "127.0.0.1" ||
        remoteAddr == "::1" ||
        strings.HasPrefix(remoteAddr, "127.") {
        return true
    }
    
    return false
}
```

#### 2. 加固 `getClientIP()` 函数

增加了多重防护：

1. **只有可信来源才检查代理头部**
   - 只有当 `RemoteAddr` 是本地或私有 IP 时，才信任代理头部
   - 这样可以防止公网用户伪造头部

2. **拒绝 localhost IP 作为客户端 IP**
   - 即使从代理头部读取到 `127.0.0.1`，也拒绝使用
   - 防止攻击者将自己伪装成 localhost

3. **拒绝私有 IP 作为客户端 IP**
   - 只返回公网 IP
   - 防止攻击者伪装成内网用户

**核心逻辑：**
```go
func (s *Server) getClientIP(r *http.Request) string {
    // 获取真实的连接来源
    remoteIP := r.RemoteAddr
    if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
        remoteIP = remoteIP[:idx]
    }
    
    // 只有可信来源（本地/私有IP）才检查代理头部
    isTrustedSource := s.isPrivateIP(remoteIP) || 
                       remoteIP == "127.0.0.1" || 
                       remoteIP == "::1"
    
    if isTrustedSource {
        // 检查代理头部，但拒绝 localhost/私有IP
        if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
            if !s.isLocalhostIP(cfIP) {
                return cfIP
            }
        }
        // ... 其他头部检查
    }
    
    // 默认返回真实的 RemoteAddr
    return remoteIP
}
```

#### 3. 新增 `isLocalhostIP()` 辅助函数

```go
// isLocalhostIP 检查 IP 是否为 localhost
// 用于防止攻击者伪造 HTTP 头部绕过认证
func (s *Server) isLocalhostIP(ip string) bool {
    return ip == "127.0.0.1" ||
        ip == "::1" ||
        strings.HasPrefix(ip, "127.") ||
        ip == "localhost"
}
```

---

## 测试验证

### 测试 1：攻击场景（修复前会成功，修复后失败）

```bash
# 尝试伪造 X-Real-IP
curl -H "X-Real-IP: 127.0.0.1" \
     http://your-server.com/api/git-server/apps

# 预期结果（修复后）：
# HTTP 401 Unauthorized
# {"error": "未授权访问"}
```

### 测试 2：真正的 localhost 请求（应该成功）

```bash
# 在服务器本地执行
curl http://localhost/api/git-server/apps

# 预期结果：
# HTTP 200 OK
# [应用列表]
```

### 测试 3：通过反向代理的正常请求

```bash
# 通过 Nginx/Cloudflare 等反向代理
curl http://your-server.com/api/git-server/apps \
     -H "Authorization: Bearer <token>"

# 预期结果：
# HTTP 200 OK（如果 token 有效）
# HTTP 401 Unauthorized（如果 token 无效）
```

---

## 影响范围

### 已修复的文件

- ✅ `internal/web/server.go` - 主要修复
  - `isLocalhostRequest()` - 使用 RemoteAddr 而不是 getClientIP()
  - `getClientIP()` - 增加多重防护
  - `isLocalhostIP()` - 新增辅助函数
  - `securityMiddleware()` - 使用更安全的判断方法

### 未受影响的文件

- ✅ `main.go` - 已经使用 RemoteAddr，无需修改
- ✅ `internal/web/api_runners.go` - 调用 isLocalhostRequest()，间接修复

---

## 部署建议

### 紧急程度

🔴 **立即部署**

这是一个严重的安全漏洞，允许攻击者绕过认证。建议尽快部署修复版本。

### 部署步骤

```bash
# 1. 编译新版本
go build -o sslcat main.go

# 2. 备份当前版本
cp /path/to/sslcat /path/to/sslcat.backup

# 3. 部署新版本
cp sslcat /path/to/sslcat

# 4. 重启服务
systemctl restart sslcat
# 或
./sslcat restart
```

### 部署后验证

```bash
# 1. 测试攻击是否被阻止
curl -H "X-Real-IP: 127.0.0.1" http://your-server/api/git-server/apps
# 应该返回 401 Unauthorized

# 2. 测试正常功能
# 在服务器本地执行
curl http://localhost/api/git-server/apps
# 应该返回正常数据

# 3. 检查日志
tail -f /path/to/logs/sslcat.log
# 查看是否有异常
```

---

## 安全建议

### 长期建议

1. **最小权限原则**
   - 只对必要的 API 端点开启 localhost 豁免
   - 考虑使用 API Token 而不是 localhost 豁免

2. **网络隔离**
   - 将管理 API 部署在单独的端口
   - 使用防火墙限制对管理端口的访问

3. **审计日志**
   - 记录所有 API 调用，包括 localhost 请求
   - 定期审查日志，发现异常访问

4. **使用 HTTPS**
   - 启用 HTTPS，防止中间人攻击
   - 使用双向 TLS 认证（mTLS）

### 配置示例

```json
{
  "security": {
    "api_token": "your-secret-token-here",
    "localhost_bypass_enabled": false,  // 建议关闭
    "require_auth_for_all": true
  }
}
```

---

## 安全披露

### 漏洞发现

- 发现者：用户通过询问"如果用户把 localhost 解析到我们服务器上会怎样？"触发了深入的安全审查
- 发现日期：2025-10-08
- 修复日期：2025-10-08

### 受影响的版本

- 所有包含 localhost 认证豁免功能的版本

### 修复版本

- v1.3.11+（待发布）

---

## 相关链接

- [DDoS 检测修复](./DDOS_DETECTION_FIX.md)
- [安全分析](./SECURITY_ANALYSIS.md)
- [配置文件说明](./CONFIG_FILES.md)

