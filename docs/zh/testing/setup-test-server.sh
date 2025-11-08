#!/bin/bash

# SSLcat 模板测试服务器环境设置脚本
# 用于在 sg2.shifen.de 上设置测试环境

set -e

SERVER="root@sg2.shifen.de"
WORK_DIR="/opt/sslcat-test"
SSLCAT_DIR="/opt/sslcat"

echo "🚀 开始设置测试服务器环境..."

# 检查 SSH 连接
echo "📡 检查 SSH 连接..."
ssh -o ConnectTimeout=10 $SERVER "echo 'SSH 连接成功'" || {
    echo "❌ 无法连接到服务器，请检查 SSH 配置"
    exit 1
}

# 在服务器上执行设置命令
ssh $SERVER bash << 'ENDSSH'
set -e

echo "📦 检查系统信息..."
uname -a
df -h
free -h

echo "🔧 安装必要工具..."

# 检查并安装 Docker
if ! command -v docker &> /dev/null; then
    echo "安装 Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "✅ Docker 已安装: $(docker --version)"
fi

# 检查并安装 Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "安装 Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
else
    echo "✅ Docker Compose 已安装"
fi

# 检查并安装 Go
if ! command -v go &> /dev/null; then
    echo "安装 Go..."
    GO_VERSION="1.21.5"
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
else
    echo "✅ Go 已安装: $(go version)"
fi

# 检查并安装 Git
if ! command -v git &> /dev/null; then
    echo "安装 Git..."
    if command -v yum &> /dev/null; then
        yum install -y git
    elif command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y git
    fi
else
    echo "✅ Git 已安装: $(git --version)"
fi

# 检查并安装 jq
if ! command -v jq &> /dev/null; then
    echo "安装 jq..."
    if command -v yum &> /dev/null; then
        yum install -y jq
    elif command -v apt-get &> /dev/null; then
        apt-get install -y jq
    fi
else
    echo "✅ jq 已安装"
fi

# 创建测试目录
mkdir -p $WORK_DIR
mkdir -p $SSLCAT_DIR

echo "✅ 环境设置完成"
ENDSSH

echo "✅ 服务器环境设置完成！"
echo ""
echo "下一步："
echo "1. 克隆或同步 sslcat 代码到服务器"
echo "2. 编译 SSLcat"
echo "3. 运行测试脚本"

