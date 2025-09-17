# 阿里云OSS代理问题解决方案

## 问题概述

在使用SSLcat作为反向代理访问阿里云OSS时，遇到了403 AccessDenied错误，导致CDN策略失败。通过深入分析发现，问题主要出现在HTTP头部处理上，特别是Host头部的格式和代理相关头部的泄露。

## 问题现象

### 错误信息
```xml
<Error>
  <Code>AccessDenied</Code>
  <Message>The bucket you are attempting to access must be addressed using the specified endpoint. Please send all future requests to this endpoint.</Message>
  <RequestId>68CA2D8941CA9434390317EE</RequestId>
  <HostId>local.de:9933</HostId>
  <Bucket>questions</Bucket>
  <Endpoint>oss-cn-hangzhou.aliyuncs.com</Endpoint>
  <EC>0003-00001403</EC>
  <RecommendDoc>https://api.alibabacloud.com/troubleshoot?q=0003-00001403</RecommendDoc>
</Error>
```

### 关键问题点
1. **HostId泄露**: 阿里云OSS返回的HostId显示为`local.de:9933`，说明原始代理域名被泄露
2. **Host头部格式错误**: 发送的Host头部包含端口号`van-course.oss-ap-southeast-1.aliyuncs.com:80`
3. **代理头部干扰**: 各种代理相关头部可能触发OSS的安全检查

## 根本原因分析

### 1. Go HTTP包的特殊行为
在Go的HTTP包中，`req.Host`字段和`req.Header["Host"]`是两个不同的概念：
- `req.Host` 是请求结构体的字段，HTTP客户端优先使用此字段
- `req.Header.Get("Host")` 是HTTP头部
- 两者不同步会导致Host信息泄露

### 2. httputil.ReverseProxy的Director调用顺序
```go
// 原始Director会根据目标URL自动设置Host
originalDirector(req)
// 我们的设置可能被覆盖
req.Header.Set("Host", backendHost)
```

### 3. 云服务对Host头部的严格要求
阿里云OSS等云服务对Host头部格式有严格要求：
- ✅ 正确: `van-course.oss-ap-southeast-1.aliyuncs.com`
- ❌ 错误: `van-course.oss-ap-southeast-1.aliyuncs.com:80`

### 4. 代理头部的防盗链检查
云服务可能将以下头部视为可疑：
- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Real-IP`
- `Referer` (指向本地域名)

## 解决方案

### 1. 智能Host头部处理

#### 修改前
```go
// 简单设置Host头部，可能包含端口号
req.Header.Set("Host", backendHost)
```

#### 修改后
```go
// 检查是否为云服务
isCloudService := strings.Contains(strings.ToLower(hostname), "aliyuncs.com") ||
    strings.Contains(strings.ToLower(hostname), "amazonaws.com") ||
    strings.Contains(strings.ToLower(hostname), "qcloud.com") ||
    strings.Contains(strings.ToLower(hostname), "myqcloud.com")

// 对于云服务，移除标准端口号
if isCloudService && (urlPort == 80 || urlPort == 443) {
    return hostname  // 不包含端口号
}
```

### 2. 同步设置req.Host和Header

#### 修改前
```go
// 只设置Header，req.Host可能不同步
req.Header.Set("Host", backendHost)
```

#### 修改后
```go
// 同时设置req.Host和Header，确保同步
req.Host = backendHost
req.Header.Set("Host", backendHost)
```

### 3. 调整Director函数调用顺序

#### 修改前
```go
// 调用原始Director
originalDirector(req)
// 设置Host（可能被覆盖）
req.Header.Set("Host", backendHost)
```

#### 修改后
```go
// 保存原始Host
originalHost := req.Host
// 调用原始Director
originalDirector(req)
// 重新设置正确的Host，覆盖原始Director的设置
req.Host = backendHost
req.Header.Set("Host", backendHost)
```

### 4. 云服务头部清理策略

#### 预清理阶段
```go
// 在请求处理早期就清理代理头部
if isOSS {
    r.Header.Del("X-Forwarded-For")
    r.Header.Del("X-Forwarded-Host")
    r.Header.Del("X-Forwarded-Proto")
    r.Header.Del("X-Forwarded-Port")
    r.Header.Del("X-Real-IP")
    r.Header.Del("X-Forwarded-Server")
    r.Header.Del("X-Original-URI")
    r.Header.Del("X-Original-Method")
    
    // 处理可能导致防盗链的Referer
    if referer := r.Header.Get("Referer"); referer != "" && strings.Contains(referer, "local.") {
        r.Header.Del("Referer")
    }
}
```

#### Director函数中的二次清理
```go
// 在发送请求前再次确保清理彻底
if isOSS || cdnEnabled {
    req.Header.Del("X-Forwarded-Host")
    req.Header.Del("X-Forwarded-Server")
    req.Header.Del("X-Original-Uri")
    req.Header.Del("X-Original-Method")
    req.Header.Del("X-Forwarded-For")
    req.Header.Del("X-Real-IP")
    req.Header.Del("X-Forwarded-Proto")
    req.Header.Del("X-Forwarded-Port")
    
    // 额外的云服务头部清理
    if isOSS {
        req.Header.Del("X-Forwarded")
        req.Header.Del("X-Client-IP")
        req.Header.Del("X-Cluster-Client-IP")
        req.Header.Del("Forwarded-For")
        req.Header.Del("Forwarded")
        req.Header.Del("CF-Connecting-IP")
    }
}
```

### 5. 条件性代理头部设置

#### 修改前
```go
// 非CDN模式下总是设置代理头部
if !cdnEnabled {
    r.Header.Set("X-Forwarded-Host", r.Host)
    r.Header.Set("X-Forwarded-For", clientIP)
    // ... 其他代理头部
}
```

#### 修改后
```go
// 只有非CDN且非云服务时才设置代理头部
if !cdnEnabled && !isOSS {
    r.Header.Set("X-Forwarded-Host", r.Host)
    r.Header.Set("X-Forwarded-For", clientIP)
    // ... 其他代理头部
} else {
    // 云服务模式：完全避免设置代理头部
    m.log.Infof("云服务模式 enabled for %s, skipping proxy headers", r.Host)
}
```

## 技术细节

### 云服务检测逻辑
```go
func (m *Manager) isCloudService(target string) bool {
    return strings.Contains(strings.ToLower(target), "aliyuncs.com") ||
        strings.Contains(strings.ToLower(target), "amazonaws.com") ||
        strings.Contains(strings.ToLower(target), "qcloud.com") ||
        strings.Contains(strings.ToLower(target), "myqcloud.com")
}
```

### Host头部提取逻辑
```go
func (m *Manager) extractHostFromTarget(target string, port int) string {
    // 解析URL
    parsedURL, err := url.Parse(target)
    if err == nil {
        hostname := parsedURL.Hostname()
        isCloudService := m.isCloudService(hostname)
        
        // 对于云服务，如果是标准端口，则不包含端口号
        if parsedURL.Port() != "" {
            urlPort, _ := strconv.Atoi(parsedURL.Port())
            if isCloudService && (urlPort == 80 || urlPort == 443) {
                return hostname  // 不包含端口号
            }
        }
    }
    // ... 其他逻辑
}
```

### 日志追踪增强
```go
// 记录Host字段的最终状态
m.log.Infof("最终发送的Host信息 - req.Host: %s, Header['Host']: %s", 
    req.Host, req.Header.Get("Host"))
```

## 测试验证

### 修复前的问题请求
```bash
curl -H 'Host: van-course.oss-ap-southeast-1.aliyuncs.com:80' \
     -H 'X-Forwarded-For: 127.0.0.1' \
     -H 'Referer: http://local.de:9933/questions/2025/09-16/a17.png' \
     'http://van-course.oss-ap-southeast-1.aliyuncs.com:80/favicon.ico'
```

### 修复后的正确请求
```bash
curl -H 'Host: van-course.oss-ap-southeast-1.aliyuncs.com' \
     'http://van-course.oss-ap-southeast-1.aliyuncs.com:80/favicon.ico'
```

## 部署说明

### 编译要求
```bash
# 为Linux服务器编译
GOOS=linux GOARCH=amd64 go build -o withssl-linux-amd64 main.go
```

### 部署步骤
1. 停止服务: `systemctl stop sslcat`
2. 传输文件: `scp withssl-linux-amd64 root@server:/opt/sslcat/sslcat`
3. 设置权限: `chmod +x /opt/sslcat/sslcat`
4. 启动服务: `systemctl start sslcat`

## 兼容性说明

### 支持的云服务
- ✅ 阿里云OSS (aliyuncs.com)
- ✅ AWS S3 (amazonaws.com)
- ✅ 腾讯云COS (qcloud.com, myqcloud.com)
- ✅ 其他云存储服务（可扩展）

### 向后兼容
- ✅ 普通HTTP代理功能不受影响
- ✅ IP地址后端代理功能不受影响
- ✅ 非云服务域名代理功能不受影响

## 总结

通过这次修复，我们解决了以下关键问题：

1. **Host头部格式标准化** - 确保云服务接收到正确格式的Host头部
2. **代理头部泄露防护** - 完全避免向云服务发送可能触发安全检查的头部
3. **架构兼容性** - 支持多种云服务提供商
4. **调试能力增强** - 添加详细的日志追踪功能

这个解决方案不仅修复了阿里云OSS的问题，还增强了对其他云服务的兼容性，为未来的扩展提供了良好的基础。

---

**修复版本**: SSLcat v1.2.2  
**提交ID**: 25bc4dd  
**修复日期**: 2025-09-17
