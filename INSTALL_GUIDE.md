# SSLcat 安装指南

SSLcat 提供多种安装方式，满足不同用户的需求。

## 🚀 快速安装（推荐）

### 方法一：一键自动安装

```bash
# 从GitHub下载并运行安装脚本
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh
sudo bash install.sh
```

**优势**：
- ✅ 完全自动化安装
- ✅ 自动配置systemd服务
- ✅ 自动配置防火墙
- ✅ 自动创建用户和目录

---

### 方法二：嵌入式单文件部署

```bash
# 1. 克隆项目
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# 2. 生成部署包
./deploy-embedded.sh linux

# 3. 上传到服务器
scp -r deploy/ user@server:/tmp/withssl-deploy

# 4. 服务器上一键部署
ssh user@server "cd /tmp/withssl-deploy && sudo bash deploy-commands.sh"
```

**优势**：
- ✅ 单文件部署（所有资源嵌入）
- ✅ 无外部依赖
- ✅ 版本一致性保证
- ✅ 适合生产环境

---

### 方法三：远程自动部署

```bash
# 1. 克隆项目
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# 2. 直接部署到远程服务器
./deploy.sh your-server.com root
```

**优势**：
- ✅ 直接从开发机部署
- ✅ 自动编译和上传
- ✅ 一键完成所有步骤

---

## 📋 安装方式对比

| 方式 | 适用场景 | 复杂度 | 自动化程度 | 推荐度 |
|------|---------|--------|-----------|-------|
| 一键自动安装 | 单服务器快速部署 | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 嵌入式部署 | 生产环境批量部署 | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 远程部署 | 开发测试环境 | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 手动安装 | 自定义需求 | ⭐⭐⭐⭐ | ⭐ | ⭐⭐ |
| Docker部署 | 容器化环境 | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |

---

## 🔧 高级安装选项

### Docker 容器部署

```bash
# 使用Docker Compose
docker-compose up -d
```

### 手动编译安装

```bash
# 1. 克隆源码
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# 2. 编译
go build -o withssl main.go

# 3. 手动配置
sudo mkdir -p /opt/sslcat /etc/sslcat /var/lib/sslcat
sudo cp withssl /opt/sslcat/
sudo cp withssl.conf.example /etc/sslcat/withssl.conf
# ... 更多手动步骤
```

---

## 🛠️ 系统要求

### 最低要求
- **操作系统**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)
- **架构**: x86_64 (AMD64)
- **内存**: 512MB RAM
- **存储**: 100MB 可用空间
- **网络**: 80, 443 端口可用

### 推荐配置
- **操作系统**: Ubuntu 20.04 LTS 或 CentOS 8
- **内存**: 1GB+ RAM
- **存储**: 1GB+ 可用空间
- **CPU**: 1 核心以上

---

## ⚙️ 安装后配置

### 1. 编辑配置文件

```bash
sudo nano /etc/sslcat/withssl.conf
```

### 2. 启动服务

```bash
sudo systemctl start withssl
sudo systemctl enable withssl
```

### 3. 检查状态

```bash
sudo systemctl status withssl
sudo journalctl -u withssl -f
```

### 4. 访问管理面板

```
https://your-domain/sslcat-panel/
用户名: admin
密码: admin*9527 (首次登录后请修改)
```

---

## 🔍 故障排除

### 安装失败

```bash
# 检查系统要求
uname -a
df -h
free -h

# 检查网络连接
curl -I https://github.com

# 重新运行安装
sudo bash install.sh
```

### 服务启动失败

```bash
# 检查服务状态
sudo systemctl status withssl

# 查看日志
sudo journalctl -u withssl -n 50

# 检查配置
sudo /opt/sslcat/withssl --config /etc/sslcat/withssl.conf --check

# 修复权限
sudo chown -R withssl:withssl /opt/sslcat /etc/sslcat /var/lib/sslcat
```

### 端口被占用

```bash
# 检查端口占用
sudo netstat -tlnp | grep ':443'
sudo netstat -tlnp | grep ':80'

# 停止冲突服务
sudo systemctl stop nginx  # 如果使用nginx
sudo systemctl stop apache2  # 如果使用apache
```

---

## 🚨 安全建议

### 1. 修改默认密码
登录管理面板后立即修改默认密码

### 2. 配置防火墙
```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp  
sudo ufw allow 443/tcp
sudo ufw enable

# firewalld (CentOS)
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

### 3. 定期更新
```bash
# 使用自动更新脚本
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/update.sh | sudo bash
```

---

## 📞 获取支持

如果遇到安装问题：

1. 📖 查看 [故障排除文档](DEPLOYMENT.md#故障排除)
2. 🔍 搜索 [GitHub Issues](https://github.com/xurenlu/sslcat/issues)
3. 🆕 创建新的 Issue
4. 💬 加入社区讨论

---

## 📝 快速命令参考

```bash
# 查看服务状态
sudo systemctl status withssl

# 重启服务
sudo systemctl restart withssl

# 查看实时日志
sudo journalctl -u withssl -f

# 编辑配置
sudo nano /etc/sslcat/withssl.conf

# 测试配置
sudo /opt/sslcat/withssl --config /etc/sslcat/withssl.conf --check

# 修复服务（如遇路径问题）
sudo bash fix-service.sh
```
