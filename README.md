# SSLcat - SSL 代理服务器

## ⏱️ 一分钟快速上手 SSLcat

```bash
# 1) 一键安装（Linux）
# 面向中国大陆用户（通过 sslcat.com 加速）
curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.0.2
# 非大陆用户可直接使用 GitHubusercontent：
# curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.0.2

# 2) macOS 本地快速试用（或自行下载 darwin 包）
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.0.2/withssl_1.0.2_darwin_arm64.tar.gz -o withssl.tgz
tar -xzf withssl.tgz && sudo install -m 0755 withssl /usr/local/bin/withssl
withssl --config withssl.conf --port 8080
# 浏览器访问: http://localhost:8080/withssl-panel/
# 首次登录：admin / admin*9527（会强制要求修改密码并生成 admin.pass）

# 3) 可选：Docker Compose 一键起
docker compose up -d
```


SSLcat 是一个功能强大的 SSL 代理服务器，支持自动证书管理、域名转发、安全防护和 Web 管理面板。

## 📚 文档导航

- 📑 [完整文档目录](DOCS.md) - 所有文档的索引和导航
- 📖 [项目总结](项目总结.md) - 详细的功能介绍和技术说明
- 🚀 [部署指南 (中文)](DEPLOYMENT.md) - 完整的部署和运维文档
- 🚀 [Deployment Guide (English)](DEPLOYMENT_EN.md) - English deployment guide

### 🌍 多语言版本
- 🇺🇸 [English README](README_EN.md) - English version
- 🇯🇵 [日本語 README](README_JA.md) - Japanese version  
- 🇪🇸 [Español README](README_ES.md) - Spanish version
- 🇫🇷 [Français README](README_FR.md) - French version
- 🇷🇺 [Русский README](README_RU.md) - Russian version

## 功能特性

### 🌏 中国大陆网络优化
- **CDN 代理优化**: 使用 [CDNProxy](https://cdnproxy.some.im/docs) 代理服务
- **访问加速**: 解决中国大陆访问 jsdelivr CDN 的网络问题
- **稳定可靠**: 通过代理确保资源加载的稳定性

### 🔒 自动 SSL 证书管理
- 自动从 Let's Encrypt 获取 SSL 证书
- 支持证书自动续期
- 支持测试环境和生产环境
- 证书缓存和性能优化

### 🔄 智能域名转发
- 基于域名的智能代理转发
- 支持 HTTP/HTTPS 协议
- WebSocket 代理支持
- 连接池和负载均衡

### 🛡️ 安全防护机制
- IP 封禁和访问控制
- 防暴力破解保护
- User-Agent 验证
- 访问日志记录

### 🎛️ Web 管理面板
- 直观的 Web 界面
- 实时监控和统计
- 代理规则管理
- SSL 证书管理
- 安全设置配置

### 🔄 平滑重启
- 零停机时间重启
- 连接保持和状态恢复
- 优雅关闭机制

## 系统要求

- Linux 系统 (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 或更高版本
- Root 权限
- 80 和 443 端口可用

## 📥 获取源码

### GitHub 仓库

项目托管在GitHub上：**[https://github.com/xurenlu/sslcat](https://github.com/xurenlu/sslcat)**

### 最新版本下载

```bash
# 克隆最新源码
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# 或者下载指定版本（推荐）
wget https://github.com/xurenlu/sslcat/archive/refs/heads/main.zip
unzip main.zip
cd withssl-main
```

## 🚀 快速安装

### 自动安装（推荐）

```bash
# 从GitHub下载安装脚本
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh

# 运行安装脚本
sudo bash install.sh
```

### 嵌入式部署（单文件）

```bash
# 生成嵌入式部署包
./deploy-embedded.sh

# 或生成Linux版本
./deploy-embedded.sh linux

# 然后上传deploy/目录到服务器即可
```

### 手动安装

1. **安装依赖**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y curl wget git build-essential ca-certificates certbot

# CentOS/RHEL
sudo yum update -y
sudo yum install -y curl wget git gcc gcc-c++ make ca-certificates certbot
```

2. **安装 Go**
```bash
# 下载并安装 Go 1.21
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

3. **编译 SSLcat**
```bash
git clone https://github.com/xurenlu/sslcat.git
cd withssl
go mod download
go build -o withssl main.go
```

4. **创建用户和目录**
```bash
sudo useradd -r -s /bin/false withssl
sudo mkdir -p /etc/withssl /var/lib/withssl/{certs,keys,logs}
sudo chown -R withssl:withssl /var/lib/withssl
```

5. **配置和启动**
```bash
sudo cp withssl /opt/withssl/
sudo cp withssl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable withssl
sudo systemctl start withssl
```

## 配置说明

### 配置文件位置
- 主配置文件: `/etc/withssl/withssl.conf`
- 证书目录: `/var/lib/withssl/certs`
- 密钥目录: `/var/lib/withssl/keys`
- 日志目录: `/var/lib/withssl/logs`

### 基本配置

```yaml
server:
  host: "0.0.0.0"
  port: 443
  debug: false

ssl:
  email: "your-email@example.com"  # SSL证书邮箱
  staging: false                   # 是否使用测试环境
  auto_renew: true                 # 自动续期

admin:
  username: "admin"
  password_file: "./data/admin.pass"     # 密码保存在此文件，withssl.conf不持久化password
  first_run: true

proxy:
  rules:
    - domain: "example.com"
      target: "127.0.0.1"
      port: 8080
      enabled: true
      ssl_only: true

security:
  max_attempts: 3                  # 1分钟内最大失败次数
  block_duration: "1m"             # 封禁时长
  max_attempts_5min: 10            # 5分钟内最大失败次数

admin_prefix: "/withssl-panel"     # 管理面板路径前缀
```

### 忘记密码（紧急恢复）

withssl 采用“标记文件 + 首次强制改密”的安全策略：

- 标记文件：`admin.password_file`（默认 `./data/admin.pass`）。文件以 0600 权限保存当前管理员密码。
- 首次登录：若标记文件不存在，或文件内容仍为默认密码 `admin*9527`，管理员登录成功后会被强制跳转到“修改密码”页设置新密码，并写入标记文件。

忘记密码恢复步骤：

1. 停止服务（或保持运行亦可，推荐停止）。
2. 删除标记文件（若路径有变更，请按配置实际路径删除）：
   ```bash
   rm -f ./data/admin.pass
   ```
3. 重新启动服务，使用默认账户登录（admin / admin*9527）。
4. 系统将强制进入“修改密码”页，设置新密码后恢复正常。

说明：出于安全考虑，`withssl.conf` 在保存时不再持久化 `admin.password` 明文；运行时真实密码以 `admin.password_file` 为准。

## 使用方法

### 启动服务
```bash
sudo systemctl start withssl
```

### 停止服务
```bash
sudo systemctl stop withssl
```

### 重启服务
```bash
sudo systemctl restart withssl
```

### 平滑重启
```bash
sudo systemctl reload withssl
# 或者发送 SIGHUP 信号
sudo kill -HUP $(pgrep withssl)
```

### 查看日志
```bash
# 查看服务状态
sudo systemctl status withssl

# 查看实时日志
sudo journalctl -u withssl -f

# 查看错误日志
sudo journalctl -u withssl -p err
```

## Web 管理面板

### 访问管理面板
1. 打开浏览器访问: `https://your-domain/withssl-panel`
2. 使用默认用户名和密码登录:
   - 用户名: `admin`
   - 密码: `admin*9527`
3. 首次登录后请立即修改密码

### 管理面板功能
- **仪表板**: 查看系统状态和统计信息
- **代理配置**: 管理域名转发规则
- **SSL证书**: 查看和管理SSL证书
- **安全设置**: 配置安全策略和查看封禁IP
- **系统设置**: 修改系统配置

## 代理配置

### 添加代理规则
1. 登录管理面板
2. 进入"代理配置"页面
3. 点击"新建代理规则"
4. 填写配置信息:
   - 域名: 要代理的域名
   - 目标地址: 后端服务器IP或域名
   - 端口: 后端服务端口
   - 启用状态: 是否启用此规则
   - SSL仅限: 是否仅允许HTTPS访问

### 代理规则示例
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "127.0.0.1"
      port: 3000
      enabled: true
      ssl_only: true
    - domain: "app.example.com"
      target: "192.168.1.100"
      port: 8080
      enabled: true
      ssl_only: false
```

## SSL 证书管理

### 自动获取证书
SSLcat 会自动为配置的域名获取 SSL 证书，无需手动操作。

### 证书续期
证书会在到期前30天自动续期，也可以手动触发续期。

### 证书存储
- 证书文件: `/var/lib/withssl/certs/domain.crt`
- 私钥文件: `/var/lib/withssl/keys/domain.key`

## 安全功能

### IP 封禁机制
- 1分钟内失败3次自动封禁
- 5分钟内失败10次自动封禁
- 封禁时长可配置
- 支持手动解除封禁

### 访问控制
- User-Agent 验证
- 空 User-Agent 拒绝访问
- 非常见浏览器 User-Agent 拒绝访问

### 解除封禁
```bash
# 删除封禁文件重启服务
sudo rm /var/lib/withssl/withssl.block
sudo systemctl restart withssl
```

## 命令行参数

```bash
withssl [选项]

选项:
  --config string        配置文件路径 (默认: "/etc/withssl/withssl.conf")
  --admin-prefix string  管理面板路径前缀 (默认: "/withssl-panel")
  --email string         SSL证书邮箱
  --staging             使用Let's Encrypt测试环境
  --port int            监听端口 (默认: 443)
  --host string         监听地址 (默认: "0.0.0.0")
  --log-level string    日志级别 (默认: "info")
  --version             显示版本信息
```

## 故障排除

### 常见问题

1. **服务启动失败**
   ```bash
   # 检查配置文件语法
   sudo withssl --config /etc/withssl/withssl.conf --log-level debug
   
   # 检查端口占用
   sudo netstat -tlnp | grep :443
   ```

2. **SSL证书获取失败**
   - 确保域名解析正确
   - 确保80端口可访问
   - 检查防火墙设置
   - 使用测试环境验证

3. **代理转发失败**
   - 检查目标服务器是否可达
   - 验证端口是否正确
   - 查看访问日志

4. **管理面板无法访问**
   - 检查防火墙设置
   - 验证SSL证书是否有效
   - 查看服务日志

### 日志分析
```bash
# 查看详细日志
sudo journalctl -u withssl -f --no-pager

# 过滤错误日志
sudo journalctl -u withssl -p err --since "1 hour ago"

# 查看特定时间段的日志
sudo journalctl -u withssl --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
```

## 性能优化

### 系统优化
```bash
# 增加文件描述符限制
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# 优化网络参数
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### 配置优化
```yaml
server:
  # 启用调试模式进行性能分析
  debug: false
  
proxy:
  # 合理配置代理规则数量
  rules: []
  
security:
  # 调整安全参数
  max_attempts: 5
  block_duration: "5m"
```

## 网络优化说明

### 中国大陆用户优化

SSLcat 项目已针对中国大陆网络环境进行了优化，使用了 [CDNProxy](https://cdnproxy.some.im/docs) 代理服务来解决访问 jsdelivr CDN 的网络问题。

#### 使用的 CDN 代理
- **原始地址**: `https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`
- **代理地址**: `https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`

#### 涉及的资源文件
- Bootstrap 5.1.3 CSS
- Bootstrap Icons 1.7.2
- Bootstrap 5.1.3 JavaScript
- Axios JavaScript 库

#### 访问控制
根据 CDNProxy 文档，该服务实施了访问控制策略。如果遇到访问被阻止的情况，通常是因为请求的 Referer 域名不在白名单中。如有需要，请联系服务管理员将域名加入白名单。

## 开发指南

### 项目结构
```
withssl/
├── main.go                 # 主程序入口
├── go.mod                  # Go模块文件
├── internal/               # 内部包
│   ├── config/            # 配置管理
│   ├── logger/            # 日志管理
│   ├── ssl/               # SSL证书管理
│   ├── proxy/             # 代理管理
│   ├── security/          # 安全管理
│   ├── web/               # Web服务器
│   └── graceful/          # 平滑重启
├── web/                   # Web资源
│   ├── templates/         # HTML模板
│   └── static/            # 静态资源
├── install.sh             # 安装脚本
└── README.md              # 说明文档
```

### 开发环境搭建
```bash
# 克隆项目
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# 安装依赖
go mod download

# 运行开发服务器
go run main.go --config withssl.conf --log-level debug
```

### 贡献指南
1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 支持

如果您遇到问题或有建议，请：
1. 查看 [故障排除](#故障排除) 部分
2. 搜索 [Issues](https://github.com/xurenlu/sslcat/issues)
3. 创建新的 Issue
4. 联系维护者

## 更新日志

### v1.0.0 (2024-01-01)
- 初始版本发布
- 支持自动SSL证书管理
- 支持域名代理转发
- 支持Web管理面板
- 支持安全防护机制
- 支持平滑重启功能
