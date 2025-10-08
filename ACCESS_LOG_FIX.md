# AccessLog 功能修复说明

## 问题诊断

您的 sslcat 服务器无法记录 accessLog 的原因有**两个**：

### 1. 配置被禁用 ❌
在 `sslcat.conf` 中，`access_log_enabled` 被设置为 `false`

### 2. 代码缺少实现 ❌
虽然系统初始化了 `AccessLogger`，但在代码中没有实际调用它来记录请求。

## 已完成的修复

### ✅ 修改 1: 启用配置
**文件**: `sslcat.conf`
```json
{
  "server": {
    "access_log_enabled": true,  // 已从 false 改为 true
    "access_log_format": "nginx",
    "access_log_path": "./data/access.log",
    "access_log_max_size": 104857600,
    "access_log_max_files": 10
  }
}
```

### ✅ 修改 2: 增强 ResponseWriter
**文件**: `internal/web/statistics.go`

为现有的 `responseWriter` 类型添加了字节计数功能：
```go
type responseWriter struct {
    http.ResponseWriter
    statusCode int
    written    int64  // 新增：记录发送的字节数
}

// 新增：Write 方法记录字节数
func (rw *responseWriter) Write(b []byte) (int, error) {
    n, err := rw.ResponseWriter.Write(b)
    rw.written += int64(n)
    return n, err
}
```

### ✅ 修改 3: 实现日志记录
**文件**: `internal/web/server.go`

在 `ServeHTTP` 函数中添加了 accessLog 记录逻辑：

```go
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // 记录请求开始时间
    startTime := time.Now()
    
    // 包装 ResponseWriter 以捕获状态码和字节数
    wrappedWriter := &responseWriter{
        ResponseWriter: w,
        statusCode:     200,
        written:        0,
    }
    
    // defer 记录访问日志
    defer func() {
        if s.accessLogger != nil {
            requestDuration := time.Since(startTime)
            s.accessLogger.LogRequest(r, wrappedWriter.statusCode, wrappedWriter.written, 
                requestDuration, "", 0)
        }
    }()
    
    // ... 后续请求处理逻辑，所有地方使用 wrappedWriter 代替 w
}
```

## 部署步骤

### 1. 编译新版本
```bash
cd /Users/rocky/Sites/sslcat
go build -o sslcat
```

### 2. 备份现有二进制文件（可选）
```bash
cp sslcat sslcat.backup
```

### 3. 重启服务
根据您的部署方式选择：

#### 方式 A: systemd 服务
```bash
sudo systemctl restart sslcat
```

#### 方式 B: 直接运行
```bash
# 停止旧进程
pkill sslcat

# 启动新版本
./sslcat -config=sslcat.conf
```

### 4. 验证功能

#### 发送测试请求
```bash
# 替换为您服务器的实际端口
curl http://localhost:9942/
curl http://localhost:9942/test
```

#### 检查日志文件
```bash
# 查看 access.log
tail -f data/access.log
```

期望看到类似以下格式的日志（Nginx 格式）：
```
127.0.0.1 - - [07/Oct/2025:14:30:15 +0800] "GET / HTTP/1.1" 200 1024 "-" "curl/8.7.1" 0.050 ""
127.0.0.1 - - [07/Oct/2025:14:30:16 +0800] "GET /test HTTP/1.1" 404 153 "-" "curl/8.7.1" 0.002 ""
```

## 日志格式说明

### Nginx 格式（默认）
```
IP - - [时间] "方法 URL 协议" 状态码 字节数 "Referer" "User-Agent" 请求耗时 "上游地址"
```

### 可选格式

您可以在配置文件中修改 `access_log_format` 为以下值：
- `"nginx"` - Nginx Combined 格式（默认）
- `"apache"` - Apache Combined 格式
- `"json"` - JSON 格式（便于日志分析）

## 配置选项说明

| 配置项 | 说明 | 默认值 |
|-------|------|--------|
| `access_log_enabled` | 是否启用访问日志 | `true` |
| `access_log_format` | 日志格式 | `"nginx"` |
| `access_log_path` | 日志文件路径 | `"./data/access.log"` |
| `access_log_max_size` | 单个日志文件最大大小（字节） | `104857600` (100MB) |
| `access_log_max_files` | 保留的日志文件数量 | `10` |

## 日志轮转

当日志文件达到 `access_log_max_size` 时，会自动轮转：
- 当前文件重命名为 `access.log.20251007-143015`
- 创建新的 `access.log` 文件
- 自动清理超过 `access_log_max_files` 数量的旧文件

## 故障排查

### 1. 日志文件不存在或为空
```bash
# 检查配置是否已启用
grep "access_log_enabled" sslcat.conf

# 检查目录权限
ls -la data/

# 手动创建目录（如果不存在）
mkdir -p data/
chmod 755 data/
```

### 2. 日志无法写入
```bash
# 检查磁盘空间
df -h

# 检查文件权限
ls -la data/access.log

# 查看应用日志中的错误信息
journalctl -u sslcat -n 50
# 或
cat /var/log/sslcat.log
```

### 3. 服务器运行但没有日志
确保使用的是新编译的版本：
```bash
# 检查运行的进程
ps aux | grep sslcat

# 确认二进制文件是最新的
ls -lh sslcat
./sslcat -version  # 如果支持的话
```

## 监控建议

### 实时监控访问日志
```bash
tail -f data/access.log
```

### 统计请求数
```bash
# 统计今天的请求数
grep "$(date +%d/%b/%Y)" data/access.log | wc -l

# 统计状态码分布
awk '{print $9}' data/access.log | sort | uniq -c | sort -rn
```

### 找出最慢的请求
```bash
# 按响应时间排序（第11个字段）
sort -t' ' -k11 -rn data/access.log | head -20
```

---

## 总结

✅ 配置文件已更新（`access_log_enabled: true`）  
✅ 代码已修复（添加了日志记录功能）  
✅ 项目已编译通过  

**下一步**：在您的服务器上重新编译并重启 sslcat 服务，即可开始记录访问日志。

