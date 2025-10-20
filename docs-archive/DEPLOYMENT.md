# SSLcat 部署指南

本文档详细说明如何在不同环境中部署 SSLcat。

## 📚 相关文档

- 📖 [主要说明文档](README.md) - 详细使用说明和配置指南
- 📋 [项目总结](项目总结.md) - 详细的功能介绍和技术说明
- 🇺🇸 [English README](README_EN.md) - English documentation

## 🎯 快速部署

### 方法 1: 使用部署脚本（推荐）

在 Mac/Linux 开发机上：

```bash
# 1. 构建 Linux 版本并创建部署包
./deploy.sh your-server.com root

# 2. 上传到服务器
scp -r deploy/ root@your-server.com:/tmp/

# 3. 在服务器上安装
ssh root@your-server.com 'cd /tmp/deploy && bash deploy-commands.sh'
```

### 方法 2: 使用 Makefile

```bash
# 构建 Linux 版本
make build-linux

# 手动上传
scp build/withssl-linux-amd64 root@your-server.com:/opt/sslcat/withssl
scp withssl.conf.example root@your-server.com:/etc/sslcat/withssl.conf
```

## 🔧 交叉编译说明

### 支持的平台

SSLcat 支持以下平台的交叉编译：

| 平台 | 架构 | 命令 | 用途 |
|------|------|------|------|
| **Linux** | AMD64 | `make build-linux` | 🎯 **服务器部署（推荐）** |
| Linux | ARM64 | `GOOS=linux GOARCH=arm64 go build` | ARM 服务器 |
| macOS | AMD64 | `GOOS=darwin GOARCH=amd64 go build` | Intel Mac |
| macOS | ARM64 | `GOOS=darwin GOARCH=arm64 go build` | M1/M2 Mac |
| Windows | AMD64 | `GOOS=windows GOARCH=amd64 go build` | Windows 服务器 |

### 验证编译结果

```bash
# 编译 Linux 版本
GOOS=linux GOARCH=amd64 go build -o withssl-linux main.go

# 验证文件类型
file withssl-linux
# 输出: withssl-linux: ELF 64-bit LSB executable, x86-64...

# 检查文件大小
ls -lh withssl-linux
```

## 📋 部署清单

### 必需文件

```
deploy/
├── withssl                 # Linux 64位二进制文件
├── withssl.conf           # 配置文件
├── withssl.service        # systemd 服务文件
└── deploy-commands.sh     # 服务器端安装脚本
```

### 可选文件

```
deploy/
├── install.sh            # 完整安装脚本
├── README.md             # 说明文档
└── ssl-certs/           # 预置证书（如有）
```

## 🚀 部署步骤详解

### 步骤 1: 本地构建

```bash
# 方法 A: 使用部署脚本
./deploy.sh

# 方法 B: 手动构建
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o withssl main.go
```

### 步骤 2: 准备服务器

在目标服务器上：

```bash
# 创建用户和目录
sudo useradd -r -s /bin/false withssl
sudo mkdir -p /etc/sslcat /opt/sslcat/{certs,keys,logs}
sudo chown -R withssl:withssl /opt/sslcat
```

### 步骤 3: 上传文件

```bash
# 上传二进制文件
scp withssl root@server:/opt/sslcat/
ssh root@server 'chmod +x /opt/sslcat/withssl'

# 上传配置文件
scp withssl.conf root@server:/etc/sslcat/
ssh root@server 'chown withssl:withssl /etc/sslcat/withssl.conf'
```

### 步骤 4: 安装系统服务

```bash
# 创建 systemd 服务文件
cat > /etc/systemd/system/withssl.service << 'EOF'
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/withssl --config /etc/sslcat/withssl.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 启用并启动服务
sudo systemctl daemon-reload
sudo systemctl enable withssl
sudo systemctl start withssl
```

## 🔍 部署验证

### 检查服务状态

```bash
# 查看服务状态
sudo systemctl status withssl

# 查看日志
sudo journalctl -u withssl -f

# 检查端口监听
sudo netstat -tlnp | grep :443
```

### 测试功能

```bash
# 测试管理面板
curl -k https://your-domain/sslcat-panel/login

# 测试 API
curl -k https://your-domain/sslcat-panel/api/stats
```

## 🛠️ 常见部署问题

### 问题 1: 二进制文件无法执行

```bash
# 检查文件权限
ls -la /opt/sslcat/withssl

# 设置执行权限
sudo chmod +x /opt/sslcat/withssl

# 检查文件类型
file /opt/sslcat/withssl
```

### 问题 2: 权限问题

```bash
# 检查目录权限
ls -la /opt/sslcat
ls -la /etc/sslcat

# 修复权限
sudo chown -R withssl:withssl /opt/sslcat
sudo chown withssl:withssl /etc/sslcat/withssl.conf
```

### 问题 3: 端口被占用

```bash
# 检查端口占用
sudo netstat -tlnp | grep :443

# 修改配置文件端口
sudo nano /etc/sslcat/withssl.conf
```

### 问题 4: 防火墙问题

```bash
# Ubuntu/Debian
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

## 🔄 更新部署

### 快速更新

```bash
# 1. 在开发机编译新版本
GOOS=linux GOARCH=amd64 go build -o withssl main.go

# 2. 上传新版本
scp withssl root@server:/opt/sslcat/withssl-new

# 3. 平滑重启
ssh root@server '
  sudo systemctl stop withssl
  sudo mv /opt/sslcat/withssl-new /opt/sslcat/withssl
  sudo chmod +x /opt/sslcat/withssl
  sudo systemctl start withssl
'
```

### 使用平滑重启

```bash
# 发送 SIGHUP 信号进行平滑重启
ssh root@server 'sudo systemctl reload withssl'
```

## 📊 生产环境建议

### 性能优化

```bash
# 1. 增加文件描述符限制
echo "withssl soft nofile 65536" >> /etc/security/limits.conf
echo "withssl hard nofile 65536" >> /etc/security/limits.conf

# 2. 优化网络参数
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### 监控设置

```bash
# 设置日志轮转
cat > /etc/logrotate.d/withssl << 'EOF'
/opt/sslcat/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### 备份策略

```bash
# 备份配置和证书
tar -czf withssl-backup-$(date +%Y%m%d).tar.gz \
    /etc/sslcat/ \
    /opt/sslcat/certs/ \
    /opt/sslcat/keys/
```

## 🎯 总结

| 部署方式 | 适用场景 | 优点 | 缺点 |
|----------|----------|------|------|
| **deploy.sh** | 生产环境 | 快速、可控 | 需要手动执行 |
| **install.sh** | 新环境 | 全自动 | 依赖网络 |
| **手动部署** | 特殊需求 | 完全控制 | 步骤复杂 |

**推荐流程：**
1. 🧪 **测试环境**: 使用 `install.sh` 快速搭建
2. 🚀 **生产环境**: 使用 `deploy.sh` 精确控制
3. 🔄 **日常更新**: 使用 `deploy.sh` 或手动更新
