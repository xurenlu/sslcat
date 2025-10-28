# 安装方法

本指南介绍 SSLcat 的安装方法。我们提供预编译的二进制文件，下载后运行安装脚本即可完成安装。

## 下载安装包

### 下载二进制文件
```bash
# GitHub 下载
curl -L https://github.com/xurenlu/sslcat/releases/download/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# CDN 镜像下载（推荐国内用户）
curl -L https://cdn.wxside.com/xurenlu/sslcat/releases/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# 或者使用 wget
wget https://github.com/xurenlu/sslcat/releases/download/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -O sslcat.tar.gz
```

### 解压并安装
```bash
# 解压文件
tar -xzf sslcat.tar.gz

# 运行安装脚本
sudo ./install-sslcat.sh
```

## 安装脚本说明

安装脚本 `install-sslcat.sh` 会自动完成以下操作：

1. **检查系统要求** - 验证操作系统和权限
2. **创建系统用户** - 创建 `sslcat` 用户和组
3. **创建目录结构** - 设置必要的目录和权限
4. **安装二进制文件** - 复制到系统路径并设置权限
5. **创建系统服务** - 配置 systemd 服务
6. **创建默认配置** - 生成基础配置文件
7. **启动服务** - 启用并启动 SSLcat 服务

### 安装脚本内容
```bash
#!/bin/bash
# install-sslcat.sh

set -e

# 配置变量
SSLCAT_VERSION="1.3.20-rc2"
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
    DOWNLOAD_URL="https://github.com/xurenlu/sslcat/releases/download/v${SSLCAT_VERSION}/sslcat_v${SSLCAT_VERSION}_linux-${ARCH}.tar.gz"
    
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

# 检查服务状态
systemctl status sslcat

# 检查端口
netstat -tlnp | grep sslcat
```

### 访问管理界面
```bash
# 管理界面地址
http://your-server-ip:8080/sslcat-panel

# 默认登录信息
# 用户名: admin
# 密码: admin*9527
```

## 卸载

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

## 相关文档

- [系统要求](requirements.md)
- [配置指南](../configuration/basic.md)

---

*安装完成后，请访问管理界面进行初始配置。*
