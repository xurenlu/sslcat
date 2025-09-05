# SSLcat 路径配置参考

## 📁 标准路径配置

SSLcat 项目所有安装脚本和部署工具现在使用统一的路径配置：

| 文件类型 | 路径 | 权限 | 所有者 |
|---------|------|------|--------|
| 二进制文件 | `/opt/withssl/withssl` | 755 | withssl:withssl |
| 配置文件 | `/etc/withssl/withssl.conf` | 600 | withssl:withssl |
| SSL证书目录 | `/var/lib/withssl/certs/` | 755 | withssl:withssl |
| SSL密钥目录 | `/var/lib/withssl/keys/` | 700 | withssl:withssl |
| 日志目录 | `/var/lib/withssl/logs/` | 755 | withssl:withssl |
| 封禁文件 | `/var/lib/withssl/withssl.block` | 644 | withssl:withssl |
| systemd服务 | `/etc/systemd/system/withssl.service` | 644 | root:root |

## 🔧 各脚本路径使用情况

### install.sh (完整安装)
```bash
二进制文件: /opt/withssl/withssl
配置文件: /etc/withssl/withssl.conf
数据目录: /var/lib/withssl/
用户: withssl (系统用户)
```

### deploy.sh (远程部署)
```bash
二进制文件: /opt/withssl/withssl
配置文件: /etc/withssl/withssl.conf
数据目录: /var/lib/withssl/
用户: withssl (系统用户)
```

### deploy-commands.sh (服务器端部署)
```bash
二进制文件: /opt/withssl/withssl
配置文件: /etc/withssl/withssl.conf
数据目录: /var/lib/withssl/
用户: withssl (系统用户)
```

### deploy-embedded.sh (嵌入式部署)
```bash
生成单文件二进制包含所有资源
仍然使用标准路径配置
配置文件: /etc/withssl/withssl.conf (外部文件)
```

## ⚙️ systemd 服务配置

所有脚本生成的 systemd 服务文件使用统一配置：

```ini
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=/opt/withssl
ExecStart=/opt/withssl/withssl --config /etc/withssl/withssl.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=withssl

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/withssl /etc/withssl /opt/withssl
```

## 🚨 常见路径错误

### ❌ 错误的配置
```bash
# 错误：配置文件在 /opt/withssl/ 目录
ExecStart=/opt/withssl/withssl --config /opt/withssl/withssl.conf

# 错误：二进制文件在 /usr/local/bin/
ExecStart=/usr/local/bin/withssl --config /etc/withssl/withssl.conf
```

### ✅ 正确的配置
```bash
# 正确：统一的路径配置
ExecStart=/opt/withssl/withssl --config /etc/withssl/withssl.conf
```

## 🛠️ 修复工具

如果发现路径配置错误，可以使用以下工具修复：

### fix-service.sh
```bash
# 自动检测和修复systemd服务配置
sudo bash fix-service.sh
```

### 手动检查
```bash
# 检查服务文件配置
cat /etc/systemd/system/withssl.service | grep ExecStart

# 检查文件是否存在
ls -la /opt/withssl/withssl
ls -la /etc/withssl/withssl.conf

# 检查服务状态
systemctl status withssl
```

## 📋 部署检查清单

部署前请确认：

- [ ] 二进制文件在：`/opt/withssl/withssl`
- [ ] 配置文件在：`/etc/withssl/withssl.conf`
- [ ] systemd服务配置正确
- [ ] 用户 `withssl` 存在
- [ ] 目录权限正确
- [ ] 防火墙已配置 (80, 443端口)

## 🔄 版本兼容性

| 版本 | 路径变更 | 迁移说明 |
|------|---------|----------|
| v1.0.0 | 初始版本路径不统一 | 使用 fix-service.sh 修复 |
| v1.0.1+ | 统一路径配置 | 新安装自动使用正确路径 |

---

**注意**: 所有路径配置现在完全统一，如果遇到路径相关的错误，请使用 `fix-service.sh` 脚本自动修复。
