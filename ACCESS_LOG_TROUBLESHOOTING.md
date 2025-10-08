# Access Log 故障排查指南

## 问题症状
shifen.de 服务器上 access log 没有记录日志

## 可能原因分析

### 1. ❌ Access Log 未启用

检查配置文件中是否启用了 access log：

```json
{
  "server": {
    "access_log_enabled": true,  // ← 必须为 true
    "access_log_path": "/path/to/access.log",
    "access_log_format": "nginx"  // 或 "apache", "json"
  }
}
```

**检查方法：**
```bash
# 在服务器上检查配置文件
cat sslcat.conf | grep -A 10 '"server"'

# 或者通过 API 检查
curl http://localhost/api/settings | jq '.server.access_log_enabled'
```

---

### 2. ❌ 日志路径权限问题

Access logger 需要有写入权限：

```bash
# 检查日志文件/目录权限
ls -la /path/to/access.log

# 检查所属用户
ps aux | grep sslcat

# 如果日志文件不存在，检查目录权限
ls -la /path/to/log/directory/
```

**修复方法：**
```bash
# 创建日志目录
mkdir -p /var/log/sslcat

# 修改权限
chown sslcat:sslcat /var/log/sslcat
chmod 755 /var/log/sslcat
```

---

### 3. ❌ 配置文件中日志路径为空

代码逻辑（internal/logger/access.go:71-77）：

```go
if enabled && logPath != "" {
    // 打开日志文件
} else {
    logger.writer = os.Stdout  // 输出到标准输出
}
```

如果 `logPath` 为空，日志会输出到 stdout 而不是文件！

**检查配置：**
```json
{
  "server": {
    "access_log_enabled": true,
    "access_log_path": ""  // ← 问题：空路径
  }
}
```

**修复：**
```json
{
  "server": {
    "access_log_enabled": true,
    "access_log_path": "./data/access.log"  // ← 指定路径
  }
}
```

---

### 4. ❌ 日志文件被轮转到其他位置

日志轮转后文件名会变化：

```bash
access.log              # 当前日志
access.log.20231008-150405  # 已轮转
access.log.20231007-120314  # 已轮转
```

**检查方法：**
```bash
# 查找所有访问日志文件
find /path/to/logs -name "access.log*" -ls

# 查看最新的日志
ls -lt /path/to/logs/access.log* | head -5
```

---

### 5. ❌ 程序启动时日志初始化失败

检查启动日志是否有错误：

```bash
# 查看 systemd 日志
journalctl -u sslcat -n 100 | grep -i "access"

# 或查看应用日志
tail -f /var/log/sslcat/sslcat.log | grep "access_logger"
```

可能的错误信息：
- `打开日志文件失败`
- `创建日志目录失败`
- `访问日志记录已禁用`

---

## 🔍 排查步骤

### 步骤 1：检查配置

```bash
# SSH 登录到 shifen.de
ssh user@shifen.de

# 查看配置文件
cd /path/to/sslcat
cat sslcat.conf | jq '.server | {access_log_enabled, access_log_path, access_log_format}'
```

预期输出：
```json
{
  "access_log_enabled": true,
  "access_log_path": "./data/access.log",
  "access_log_format": "nginx"
}
```

---

### 步骤 2：检查日志文件

```bash
# 检查日志文件是否存在
ls -la ./data/access.log*

# 如果不存在，检查目录
ls -la ./data/

# 查看最近是否有写入
stat ./data/access.log
```

---

### 步骤 3：测试写入权限

```bash
# 尝试手动写入测试
echo "test" >> ./data/access.log

# 如果失败，检查权限
ls -la ./data/
```

---

### 步骤 4：检查运行状态

```bash
# 查看进程
ps aux | grep sslcat

# 检查是否有错误日志
tail -f logs/sslcat.log | grep -i error
```

---

### 步骤 5：临时启用 debug 模式

修改配置启用 debug：

```json
{
  "server": {
    "debug": true,
    "access_log_enabled": true
  }
}
```

然后重启服务，查看详细日志。

---

## 🛠️ 快速修复

### 方案 1：重新启用 access log

```bash
# 1. 停止服务
systemctl stop sslcat

# 2. 创建日志目录
mkdir -p ./data
chmod 755 ./data

# 3. 检查配置文件
vim sslcat.conf

# 确保包含：
# "access_log_enabled": true
# "access_log_path": "./data/access.log"

# 4. 启动服务
systemctl start sslcat

# 5. 验证
sleep 5
curl http://localhost/
ls -la ./data/access.log
```

---

### 方案 2：通过 API 动态启用

如果支持动态配置（取决于实现）：

```bash
curl -X POST http://localhost/api/settings/access-log \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "path": "./data/access.log",
    "format": "nginx"
  }'
```

---

## 📊 验证日志是否工作

### 测试 1：发送测试请求

```bash
# 发送几个测试请求
curl http://localhost/
curl http://localhost/test
curl http://localhost/api/status

# 查看日志文件
tail -5 ./data/access.log
```

预期看到：
```
127.0.0.1 - - [08/Oct/2023:15:04:05 +0800] "GET / HTTP/1.1" 200 1234 "-" "curl/7.64.1" 0.001 ""
127.0.0.1 - - [08/Oct/2023:15:04:06 +0800] "GET /test HTTP/1.1" 404 89 "-" "curl/7.64.1" 0.000 ""
127.0.0.1 - - [08/Oct/2023:15:04:07 +0800] "GET /api/status HTTP/1.1" 200 156 "-" "curl/7.64.1" 0.002 ""
```

---

### 测试 2：监控实时日志

```bash
# 在一个终端监控日志
tail -f ./data/access.log

# 在另一个终端发送请求
while true; do curl http://localhost/; sleep 1; done
```

应该实时看到日志输出。

---

## 🐛 常见配置错误

### 错误 1：相对路径问题

```json
{
  "access_log_path": "./data/access.log"  
}
```

**问题**：相对路径依赖于工作目录，如果通过 systemd 启动，工作目录可能不是你期望的。

**解决**：使用绝对路径

```json
{
  "access_log_path": "/var/log/sslcat/access.log"
}
```

---

### 错误 2：忘记创建目录

```json
{
  "access_log_path": "/var/log/sslcat/access.log"
}
```

**问题**：如果 `/var/log/sslcat` 目录不存在，会创建失败。

**解决**：确保目录存在

```bash
mkdir -p /var/log/sslcat
chown sslcat:sslcat /var/log/sslcat
```

---

### 错误 3：SELinux 阻止

在某些 Linux 发行版上，SELinux 可能阻止写入：

```bash
# 检查 SELinux 状态
getenforce

# 如果是 Enforcing，可能需要调整策略
# 临时禁用（不推荐）
setenforce 0

# 或者添加正确的上下文
chcon -t httpd_log_t /var/log/sslcat/access.log
```

---

## 📝 配置文件示例

### 最小配置

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "access_log_enabled": true,
    "access_log_path": "./data/access.log"
  }
}
```

### 完整配置

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "debug": false,
    "access_log_enabled": true,
    "access_log_format": "nginx",
    "access_log_path": "/var/log/sslcat/access.log",
    "access_log_max_size": 104857600,
    "access_log_max_files": 10
  }
}
```

---

## 🔧 代码层面的检查

### 检查点 1：日志器是否初始化

在 `internal/web/server.go` 中：

```go:217-228:internal/web/server.go
al, err := logger.NewAccessLogger(format, cfg.Server.AccessLogPath, true)
if err == nil {
    // 设置大小限制
    if cfg.Server.AccessLogMaxSize > 0 {
        al.SetMaxSize(cfg.Server.AccessLogMaxSize)
    }
    if cfg.Server.AccessLogMaxFiles > 0 {
        al.SetMaxFiles(cfg.Server.AccessLogMaxFiles)
    }
    s.accessLogger = al
}
```

**注意**：如果 `NewAccessLogger` 返回错误，`accessLogger` 会是 `nil`！

---

### 检查点 2：enabled 参数

注意这里硬编码传入了 `true`：

```go
logger.NewAccessLogger(format, cfg.Server.AccessLogPath, true)
```

这个 `true` 应该来自配置：

```go
logger.NewAccessLogger(format, cfg.Server.AccessLogPath, cfg.Server.AccessLogEnabled)
```

**这可能是 BUG！** 即使配置中 `access_log_enabled: false`，也会创建日志器。

---

## 🎯 最可能的原因

基于代码分析，最可能的原因是：

1. ⭐ **配置文件中 `access_log_path` 为空字符串**
2. ⭐ **日志目录权限不足**
3. ⭐ **配置文件中 `access_log_enabled` 为 false**

---

## 💡 建议的解决方案

1. **检查配置文件**
   ```bash
   cat sslcat.conf | grep -A 3 access_log
   ```

2. **设置正确的配置**
   ```json
   {
     "server": {
       "access_log_enabled": true,
       "access_log_path": "./data/access.log",
       "access_log_format": "nginx"
     }
   }
   ```

3. **确保目录存在**
   ```bash
   mkdir -p ./data
   chmod 755 ./data
   ```

4. **重启服务**
   ```bash
   systemctl restart sslcat
   ```

5. **验证**
   ```bash
   curl http://localhost/
   cat ./data/access.log
   ```

---

需要远程协助？提供以下信息：
- 配置文件内容（隐藏敏感信息）
- `ls -la ./data/` 输出
- `ps aux | grep sslcat` 输出
- 启动日志


