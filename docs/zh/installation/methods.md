# 安装方法

本指南介绍 SSLcat 的多种安装方法，包括二进制安装、Docker 安装、源码编译和包管理器安装。

## 二进制安装

### 下载二进制文件
```bash
# 下载最新版本
curl -L https://github.com/xurenlu/sslcat/releases/latest/download/sslcat_linux_amd64.tar.gz | tar xz

# 或者使用 wget
wget https://github.com/xurenlu/sslcat/releases/latest/download/sslcat_linux_amd64.tar.gz
tar -xzf sslcat_linux_amd64.tar.gz
```

### 安装到系统
```bash
# 复制到系统路径
sudo cp sslcat /usr/local/bin/
sudo chmod +x /usr/local/bin/sslcat

# 创建配置目录
sudo mkdir -p /etc/sslcat
sudo mkdir -p /var/log/sslcat
sudo mkdir -p /var/lib/sslcat
```

### 创建系统服务
```bash
# 创建 systemd 服务文件
sudo tee /etc/systemd/system/sslcat.service > /dev/null <<EOF
[Unit]
Description=SSLcat Proxy Server
After=network.target

[Service]
Type=simple
User=sslcat
Group=sslcat
ExecStart=/usr/local/bin/sslcat -config /etc/sslcat/sslcat.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 创建用户
sudo useradd -r -s /bin/false sslcat

# 设置权限
sudo chown -R sslcat:sslcat /etc/sslcat
sudo chown -R sslcat:sslcat /var/log/sslcat
sudo chown -R sslcat:sslcat /var/lib/sslcat

# 启用服务
sudo systemctl daemon-reload
sudo systemctl enable sslcat
sudo systemctl start sslcat
```

## Docker 安装

### 基本 Docker 运行
```bash
# 拉取镜像
docker pull xurenlu/sslcat:latest

# 运行容器
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v $(pwd)/sslcat.conf:/app/sslcat.conf \
  xurenlu/sslcat:latest
```

### Docker Compose 安装
```yaml
# docker-compose.yml
version: '3.8'

services:
  sslcat:
    image: xurenlu/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./sslcat.conf:/app/sslcat.conf
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - SSLCAT_LOG_LEVEL=info
    restart: unless-stopped
```

```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f sslcat
```

## 源码编译

### 安装 Go
```bash
# 安装 Go 1.21+
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 设置环境变量
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# 验证安装
go version
```

### 编译 SSLcat
```bash
# 克隆源码
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# 安装依赖
go mod download

# 编译
go build -o sslcat .

# 或者使用 Makefile
make build
```

### 交叉编译
```bash
# 编译多平台版本
make build-all

# 或者手动编译
GOOS=linux GOARCH=amd64 go build -o sslcat-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o sslcat-windows-amd64.exe .
GOOS=darwin GOARCH=amd64 go build -o sslcat-darwin-amd64 .
```

## 包管理器安装

### Ubuntu/Debian
```bash
# 添加 GPG 密钥
wget -qO - https://repos.sslcat.com/key.gpg | sudo apt-key add -

# 添加仓库
echo "deb https://repos.sslcat.com/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/sslcat.list

# 更新包列表
sudo apt update

# 安装 SSLcat
sudo apt install sslcat
```

### CentOS/RHEL
```bash
# 添加仓库
sudo tee /etc/yum.repos.d/sslcat.repo > /dev/null <<EOF
[sslcat]
name=SSLcat Repository
baseurl=https://repos.sslcat.com/centos/\$releasever/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://repos.sslcat.com/key.gpg
EOF

# 安装 SSLcat
sudo yum install sslcat
```

### Arch Linux
```bash
# 使用 AUR
yay -S sslcat

# 或者手动安装
git clone https://aur.archlinux.org/sslcat.git
cd sslcat
makepkg -si
```

## 自动化安装脚本

### 一键安装脚本
```bash
# 下载安装脚本
curl -fsSL https://install.sslcat.com/install.sh | bash

# 或者使用 wget
wget -qO- https://install.sslcat.com/install.sh | bash
```

### 自定义安装脚本
```bash
#!/bin/bash
# install-sslcat.sh

set -e

# 配置变量
SSLCAT_VERSION="1.3.16-rc18"
SSLCAT_USER="sslcat"
SSLCAT_HOME="/opt/sslcat"
SSLCAT_CONFIG="/etc/sslcat"
SSLCAT_LOG="/var/log/sslcat"

# 检查系统要求
check_requirements() {
    echo "检查系统要求..."
    
    # 检查操作系统
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        echo "错误: 仅支持 Linux 系统"
        exit 1
    fi
    
    # 检查权限
    if [[ $EUID -ne 0 ]]; then
        echo "错误: 需要 root 权限"
        exit 1
    fi
    
    echo "系统要求检查通过"
}

# 下载 SSLcat
download_sslcat() {
    echo "下载 SSLcat ${SSLCAT_VERSION}..."
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) echo "错误: 不支持的架构 $ARCH"; exit 1 ;;
    esac
    
    # 下载二进制文件
    DOWNLOAD_URL="https://github.com/xurenlu/sslcat/releases/download/v${SSLCAT_VERSION}/sslcat_${SSLCAT_VERSION}_linux_${ARCH}.tar.gz"
    
    cd /tmp
    wget -q "$DOWNLOAD_URL" -O sslcat.tar.gz
    tar -xzf sslcat.tar.gz
    chmod +x sslcat
}

# 安装 SSLcat
install_sslcat() {
    echo "安装 SSLcat..."
    
    # 创建用户
    if ! id "$SSLCAT_USER" &>/dev/null; then
        useradd -r -s /bin/false "$SSLCAT_USER"
    fi
    
    # 创建目录
    mkdir -p "$SSLCAT_HOME"
    mkdir -p "$SSLCAT_CONFIG"
    mkdir -p "$SSLCAT_LOG"
    
    # 复制二进制文件
    cp sslcat "$SSLCAT_HOME/"
    chmod +x "$SSLCAT_HOME/sslcat"
    
    # 创建符号链接
    ln -sf "$SSLCAT_HOME/sslcat" /usr/local/bin/sslcat
    
    # 设置权限
    chown -R "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_HOME"
    chown -R "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_CONFIG"
    chown -R "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_LOG"
}

# 创建系统服务
create_service() {
    echo "创建系统服务..."
    
    cat > /etc/systemd/system/sslcat.service <<EOF
[Unit]
Description=SSLcat Proxy Server
After=network.target

[Service]
Type=simple
User=$SSLCAT_USER
Group=$SSLCAT_USER
ExecStart=$SSLCAT_HOME/sslcat -config $SSLCAT_CONFIG/sslcat.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sslcat
}

# 创建默认配置
create_config() {
    echo "创建默认配置..."
    
    cat > "$SSLCAT_CONFIG/sslcat.conf" <<EOF
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true

ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
EOF

    chown "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_CONFIG/sslcat.conf"
}

# 主函数
main() {
    echo "开始安装 SSLcat..."
    
    check_requirements
    download_sslcat
    install_sslcat
    create_service
    create_config
    
    echo "SSLcat 安装完成！"
    echo "配置文件: $SSLCAT_CONFIG/sslcat.conf"
    echo "启动服务: systemctl start sslcat"
    echo "查看状态: systemctl status sslcat"
}

# 运行主函数
main "$@"
```

## 验证安装

### 检查安装
```bash
# 检查版本
sslcat --version

# 检查配置
sslcat -config /etc/sslcat/sslcat.conf -validate

# 检查服务状态
systemctl status sslcat

# 检查端口
netstat -tlnp | grep sslcat
```

### 测试功能
```bash
# 测试 HTTP 重定向
curl -I http://example.com

# 测试 HTTPS
curl -I https://example.com

# 测试管理界面
curl http://localhost:8080/health
```

## 卸载

### 二进制安装卸载
```bash
# 停止服务
sudo systemctl stop sslcat
sudo systemctl disable sslcat

# 删除服务文件
sudo rm /etc/systemd/system/sslcat.service
sudo systemctl daemon-reload

# 删除文件
sudo rm /usr/local/bin/sslcat
sudo rm -rf /etc/sslcat
sudo rm -rf /var/log/sslcat
sudo rm -rf /var/lib/sslcat

# 删除用户
sudo userdel sslcat
```

### Docker 安装卸载
```bash
# 停止容器
docker stop sslcat
docker rm sslcat

# 删除镜像
docker rmi xurenlu/sslcat:latest

# 删除数据卷
docker volume rm sslcat-data
```

## 相关文档

- [系统要求](requirements.md)
- [安装后步骤](post-install.md)
- [配置指南](../configuration/basic.md)
- [Docker 部署](../deployment/docker.md)

---

*选择适合你环境的安装方法，确保 SSLcat 能够正常运行。*
