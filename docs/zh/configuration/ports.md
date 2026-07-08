# SSLcat 端口配置指南

## 📋 概述

SSLcat v1.3.10-rc1 引入了全新的端口配置系统，支持两种模式：**标准模式**和**自定义模式**。这个设计让用户可以根据不同的使用场景选择合适的端口配置。

## 🎯 端口模式说明

### 标准模式（推荐）

**适用场景**：生产环境、需要 HTTPS 支持

**特性**：
- 监听 80 和 443 端口
- 自动 SSL 证书申请和管理
- HTTP 到 HTTPS 自动重定向
- 完整的 HTTPS 功能支持

**配置示例**：
```json
{
  "server": {
    "port_mode": "standard",
    "enable_https": true
  }
}
```

### 自定义模式

**适用场景**：开发环境、内网部署、反向代理后端

**特性**：
- 监听单个自定义端口
- 仅支持 HTTP 协议
- 不支持 SSL 证书自动申请
- 适合开发测试

**配置示例**：
```json
{
  "server": {
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false
  }
}
```

## 🚀 使用方法

### 1. 命令行方式

#### 标准模式（默认）
```bash
# 启动标准模式，监听 80 和 443
sslcat --config sslcat.conf
```

#### 自定义模式
```bash
# 使用 --port 参数自动启用自定义模式
sslcat --config sslcat.conf --port 18080
```

### 2. 配置文件方式

#### 标准模式配置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "standard",
    "enable_https": true,
    "debug": false
  }
}
```

#### 自定义模式配置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false,
    "debug": false
  }
}
```

### 3. 前端界面配置

1. 访问管理面板：`http://your-domain/sslcat-panel/`
2. 进入 **设置** 页面
3. 在 **基础设置** 部分选择端口模式：
   - **标准模式**：显示 80/443 端口，HTTPS 开关
   - **自定义模式**：端口输入框，功能限制警告
4. 配置相应参数
5. 点击 **保存设置**

## 📊 使用场景对比

| 场景 | 推荐模式 | 端口 | 协议 | SSL 证书 | 适用环境 |
|------|----------|------|------|----------|----------|
| 生产环境 | 标准模式 | 80 + 443 | HTTP + HTTPS | 自动申请 | 公网部署 |
| 开发环境 | 自定义模式 | 18080 | HTTP | 不支持 | 本地开发 |
| 内网部署 | 自定义模式 | 3000 | HTTP | 不支持 | 内网环境 |
| 反向代理 | 自定义模式 | 18080 | HTTP | 由代理处理 | 容器化部署 |

## 🔧 配置迁移

### 自动迁移

SSLcat 会自动将旧配置迁移到新格式：

- **443 端口** → 标准模式（启用 HTTPS）
- **其他端口** → 自定义模式（禁用 HTTPS）

### 手动迁移

如果需要手动调整配置：

```json
// 旧配置
{
  "server": {
    "port": 443
  }
}

// 新配置（自动迁移后）
{
  "server": {
    "port": 443,  // 保留向后兼容
    "port_mode": "standard",
    "enable_https": true
  }
}
```

## ⚙️ 高级配置

### 标准模式高级选项

```json
{
  "server": {
    "port_mode": "standard",
    "enable_https": true,
    "host": "0.0.0.0"
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  }
}
```

### 自定义模式高级选项

```json
{
  "server": {
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false,
    "host": "0.0.0.0"
  }
}
```

## 🔍 故障排查

### 常见问题

#### 1. 端口被占用
```bash
# 检查端口占用
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443
sudo netstat -tlnp | grep :18080
```

#### 2. 权限不足
```bash
# 标准模式需要 root 权限（80/443 端口）
sudo sslcat --config sslcat.conf

# 自定义模式可以使用普通用户
sslcat --config sslcat.conf --port 18080
```

#### 3. SSL 证书问题
```bash
# 检查证书目录
ls -la /opt/sslcat/certs/
ls -la /opt/sslcat/keys/

# 查看证书状态
sslcat --config sslcat.conf --test
```

### 日志查看

```bash
# 查看服务日志
sudo journalctl -u sslcat -f

# 查看启动日志
sudo journalctl -u sslcat --since "1 hour ago"
```

## 📝 最佳实践

### 生产环境
1. 使用标准模式
2. 确保 80 和 443 端口可用
3. 配置正确的 SSL 邮箱
4. 启用自动证书续期

### 开发环境
1. 使用自定义模式
2. 选择非特权端口（18080、3000、8000）
3. 通过反向代理提供 HTTPS（如需要）

### 容器化部署
1. 使用自定义模式
2. 通过 Nginx 等反向代理提供 HTTPS
3. 使用环境变量配置端口

## 🔄 配置切换

### 从标准模式切换到自定义模式

1. 修改配置文件：
```json
{
  "server": {
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false
  }
}
```

2. 重启服务：
```bash
sudo systemctl restart sslcat
```

### 从自定义模式切换到标准模式

1. 修改配置文件：
```json
{
  "server": {
    "port_mode": "standard",
    "enable_https": true
  }
}
```

2. 重启服务：
```bash
sudo systemctl restart sslcat
```

## 📚 相关文档

- [静态站点 Builder 文档](static-builder-nginx.md)
- [端口配置设计文档](port-configuration-design.md)
- [部署指南](../DEPLOYMENT.md)
- [配置参考](../sslcat.conf.example)

## 🆘 获取帮助

如果遇到问题，可以：

1. 查看日志：`sudo journalctl -u sslcat -f`
2. 测试配置：`sslcat --config sslcat.conf --test`
3. 检查端口：`sudo netstat -tlnp | grep sslcat`
4. 查看文档：访问管理面板的帮助页面
