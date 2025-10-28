# 快速开始指南

通过这个快速开始指南，在几分钟内启动并运行 SSLcat。本指南将引导您完成安装、配置和开始使用 SSLcat 的基本步骤。

## 🚀 一分钟设置

### 前提条件
- 具有 root 访问权限的 Linux 服务器
- 指向您服务器的域名
- 端口 80 和 443 可用

### 步骤 1：下载并安装

```bash
# 下载安装包
curl -L https://github.com/xurenlu/sslcat/releases/download/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# CDN 镜像下载（推荐国内用户）
curl -L https://cdn.wxside.com/xurenlu/sslcat/releases/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# 解压并安装
tar -xzf sslcat.tar.gz
sudo ./install-sslcat.sh
```

### 步骤 2：基础配置

```bash
# 编辑配置文件
sudo nano /etc/sslcat/sslcat.conf
```

添加您的基础配置：

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true
  },
  "proxy": {
    "rules": [
      {
        "domain": "your-domain.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true
      }
    ]
  }
}
```

### 步骤 3：启动 SSLcat

```bash
# 启动服务
sudo systemctl start sslcat

# 设置开机自启
sudo systemctl enable sslcat

# 检查状态
sudo systemctl status sslcat
```

### 步骤 4：访问 Web 界面

1. 打开浏览器并访问：`http://your-server-ip/sslcat-panel`
2. 使用默认凭据登录：
   - 用户名：`admin`
   - 密码：`admin*9527`
3. 更改管理员密码并自定义面板路径
4. 配置您的第一个代理规则


## ⚙️ 初始配置

### 1. SSL 证书设置

启动 SSLcat 后，配置 SSL 证书：

1. 在 Web 界面中转到 **SSL 证书** 部分
2. 添加您的域名
3. SSLcat 将自动从 Let's Encrypt 请求证书
4. 监控证书状态

### 2. 代理规则配置

设置您的第一个代理规则：

1. 导航到 **代理配置**
2. 点击 **添加新规则**
3. 配置：
   - **域名**：`your-domain.com`
   - **目标**：`127.0.0.1`（或您的后端服务器）
   - **端口**：`8080`（或您的应用程序端口）
   - **仅 SSL**：`true`（推荐）
4. 保存并启用规则

### 3. 安全配置

配置基本安全设置：

1. 转到 **安全设置**
2. 设置：
   - **最大登录尝试次数**：3
   - **阻止持续时间**：5 分钟
   - **IP 白名单**：如需要，添加受信任的 IP
3. 保存配置

## 🔧 命令行使用

### 基本命令

```bash
# 使用自定义配置启动 SSLcat
sslcat --config /path/to/config.json --port 443

# 在调试模式下启动
sslcat --config sslcat.conf --log-level debug

# 检查版本
sslcat --version

# 显示帮助
sslcat --help
```

### 服务管理

```bash
# 启动服务
sudo systemctl start sslcat

# 停止服务
sudo systemctl stop sslcat

# 重启服务
sudo systemctl restart sslcat

# 检查状态
sudo systemctl status sslcat

# 查看日志
sudo journalctl -u sslcat -f
```

## 🌐 Web 界面概述

### 仪表板
- **系统状态**：服务健康状态和统计信息
- **活动连接**：当前代理连接
- **证书状态**：SSL 证书信息
- **安全事件**：最近的安全事件

### 代理管理
- **规则配置**：添加、编辑和删除代理规则
- **域名管理**：管理域名配置
- **后端健康**：监控后端服务器健康状态

### SSL 证书管理
- **证书列表**：查看所有证书
- **自动续期**：配置自动续期
- **证书详情**：查看证书信息

### 安全
- **访问控制**：配置安全策略
- **被阻止的 IP**：查看和管理被阻止的 IP
- **审计日志**：安全事件日志

## 🚨 故障排除

### 常见问题

**服务无法启动：**
```bash
# 检查配置语法
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# 检查端口可用性
sudo netstat -tlnp | grep :443
```

**SSL 证书问题：**
- 确保域名指向您的服务器
- 检查防火墙设置（端口 80 和 443）
- 验证配置文件中的电子邮件地址

**Web 界面无法访问：**
- 检查服务是否运行：`sudo systemctl status sslcat`
- 验证防火墙设置
- 检查日志：`sudo journalctl -u sslcat -f`

### 获取帮助

- **日志**：`sudo journalctl -u sslcat -f`
- **配置**：检查 `/etc/sslcat/sslcat.conf`
- **文档**：[完整文档](../README.md)
- **问题**：[GitHub 问题](https://github.com/xurenlu/sslcat/issues)

## 📚 下一步

现在您已经运行了 SSLcat，探索这些主题：

1. **[基础配置](configuration/basic.md)** - 了解基本配置选项
2. **[高级功能](configuration/advanced.md)** - 探索高级功能和能力
3. **[安全配置](configuration/security.md)** - 保护您的 SSLcat 安装
4. **[监控](administration/monitoring.md)** - 设置监控和告警
5. **[故障排除](troubleshooting/common-issues.md)** - 常见问题和解决方案

## 🎉 恭喜！

您已成功安装并配置了 SSLcat！您的 SSL 代理服务器现在已准备好处理 SSL 终止、证书管理和域名转发。

---

*需要帮助？查看我们的[故障排除指南](troubleshooting/common-issues.md)或[加入社区](https://github.com/xurenlu/sslcat/discussions)。*
