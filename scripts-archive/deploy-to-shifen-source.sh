#!/bin/bash

# SSLcat 源代码部署到 shifen.de 服务器并在服务器编译

set -e

TARGET_HOST="shifen.de"
TARGET_USER="rocky"
TARGET_DIR="/opt/sslcat"
TEMP_SRC_DIR="/tmp/sslcat-source-deploy"

echo "==============================================="
echo "SSLcat 源代码部署到 shifen.de（服务器编译）"
echo "==============================================="
echo "目标服务器: $TARGET_USER@$TARGET_HOST"
echo "部署目录: $TARGET_DIR"
echo ""

# 1. 创建临时目录并打包源代码
echo "📦 准备源代码包..."
rm -rf $TEMP_SRC_DIR
mkdir -p $TEMP_SRC_DIR

# 复制必要的源代码文件
echo "  - 复制 Go 源代码..."
cp -r internal $TEMP_SRC_DIR/
cp main.go $TEMP_SRC_DIR/
cp go.mod $TEMP_SRC_DIR/
cp go.sum $TEMP_SRC_DIR/
cp Makefile $TEMP_SRC_DIR/

# 复制前端代码
echo "  - 复制前端代码..."
cp -r frontend $TEMP_SRC_DIR/

# 复制 web 资源
if [ -d "web" ]; then
    echo "  - 复制 web 资源..."
    cp -r web $TEMP_SRC_DIR/
fi

if [ -d "webapp" ]; then
    echo "  - 复制 webapp 资源..."
    cp -r webapp $TEMP_SRC_DIR/
fi

# 复制配置文件示例
echo "  - 复制配置文件..."
cp sslcat.conf.example $TEMP_SRC_DIR/

# 复制脚本
if [ -d "scripts" ]; then
    echo "  - 复制脚本..."
    cp -r scripts $TEMP_SRC_DIR/
fi

# 复制 i18n 文件
if [ -d "i18n" ]; then
    echo "  - 复制 i18n 文件..."
    cp -r i18n $TEMP_SRC_DIR/
fi

# 2. 创建服务器端编译和部署脚本
cat > $TEMP_SRC_DIR/server-build-and-deploy.sh << 'EOFSCRIPT'
#!/bin/bash

set -e

TARGET_DIR="/opt/sslcat"
SRC_DIR="$(pwd)"

echo "=========================================="
echo "在服务器上编译 SSLcat"
echo "=========================================="

# 检查并安装 Node.js
echo ""
echo "🔍 检查 Node.js..."
if ! command -v node &> /dev/null; then
    echo "📦 Node.js 未安装，开始安装..."
    echo "  使用 NodeSource 仓库安装 Node.js 20.x..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    echo "✅ Node.js 安装完成"
else
    echo "✅ Node.js 已安装: $(node --version)"
fi

echo "  npm 版本: $(npm --version)"

# 检查并安装 Yarn
echo ""
echo "🔍 检查 Yarn..."
if ! command -v yarn &> /dev/null; then
    echo "📦 Yarn 未安装，开始安装..."
    sudo npm install -g yarn
    echo "✅ Yarn 安装完成"
else
    echo "✅ Yarn 已安装: $(yarn --version)"
fi

# 检查并安装 Go
echo ""
echo "🔍 检查 Go..."
GO_VERSION="1.25.1"
REQUIRED_GO_MAJOR=1
REQUIRED_GO_MINOR=21

# 检查 Go 是否已安装且版本足够新
NEED_INSTALL=false
if ! command -v go &> /dev/null; then
    echo "📦 Go 未安装"
    NEED_INSTALL=true
else
    CURRENT_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo "  当前版本: $CURRENT_VERSION"
    
    # 提取主版本号和次版本号
    CURRENT_MAJOR=$(echo $CURRENT_VERSION | cut -d. -f1)
    CURRENT_MINOR=$(echo $CURRENT_VERSION | cut -d. -f2)
    
    # 检查版本是否满足要求（需要 >= 1.21）
    if [ "$CURRENT_MAJOR" -lt "$REQUIRED_GO_MAJOR" ] || \
       ([ "$CURRENT_MAJOR" -eq "$REQUIRED_GO_MAJOR" ] && [ "$CURRENT_MINOR" -lt "$REQUIRED_GO_MINOR" ]); then
        echo "  ⚠️  版本过旧（需要 >= ${REQUIRED_GO_MAJOR}.${REQUIRED_GO_MINOR}），需要升级"
        NEED_INSTALL=true
    else
        echo "✅ Go 版本符合要求"
    fi
fi

if [ "$NEED_INSTALL" = true ]; then
    echo "📦 安装 Go ${GO_VERSION}..."
    echo "  下载 Go ${GO_VERSION}..."
    cd /tmp
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    echo "  解压并安装..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    
    # 设置环境变量
    if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
    fi
    
    # 为当前用户设置
    if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" ~/.profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    fi
    
    # 刷新 PATH 并刷新命令哈希
    export PATH=/usr/local/go/bin:$PATH
    hash -r 2>/dev/null || true
    
    cd $SRC_DIR
    echo "✅ Go ${GO_VERSION} 安装完成: $(/usr/local/go/bin/go version)"
    
    # 确保后续命令使用新的 Go
    alias go='/usr/local/go/bin/go'
fi

# 确保使用正确的 Go 路径
if [ -x "/usr/local/go/bin/go" ]; then
    export PATH=/usr/local/go/bin:$PATH
    export GOROOT=/usr/local/go
    hash -r 2>/dev/null || true
fi

# 编译前端
echo ""
echo "🔨 编译前端..."
if [ -d "frontend" ]; then
    cd frontend
    echo "  安装前端依赖..."
    yarn install
    echo "  构建前端..."
    yarn build
    cd ..
    echo "✅ 前端编译完成"
else
    echo "⚠️  未找到 frontend 目录"
fi

# 编译后端
echo ""
echo "🔨 编译后端（带 CGO 支持）..."

# 确定使用哪个 Go 命令
if [ -x "/usr/local/go/bin/go" ]; then
    GO_CMD="/usr/local/go/bin/go"
else
    GO_CMD="go"
fi

echo "  使用 Go: $($GO_CMD version)"

export CGO_ENABLED=1
export GOOS=linux
export GOARCH=amd64

echo "  下载 Go 依赖..."
$GO_CMD mod download

echo "  编译 sslcat..."
$GO_CMD build -tags="netgo,sqlite_omit_load_extension" \
    -ldflags='-s -w -extldflags "-static"' \
    -o sslcat \
    main.go

if [ ! -f "sslcat" ]; then
    echo "❌ 编译失败"
    exit 1
fi

chmod +x sslcat
echo "✅ 后端编译完成"

# 停止现有服务
echo ""
echo "🛑 停止现有服务..."
if sudo systemctl is-active --quiet sslcat; then
    sudo systemctl stop sslcat
    echo "✅ 服务已停止"
else
    echo "  服务未运行"
fi

# 创建部署目录
echo ""
echo "📁 准备部署目录..."
sudo mkdir -p $TARGET_DIR
sudo mkdir -p $TARGET_DIR/data

# 备份现有配置
if [ -f "$TARGET_DIR/sslcat.conf" ]; then
    echo "  备份现有配置..."
    sudo cp $TARGET_DIR/sslcat.conf $TARGET_DIR/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)
fi

# 复制文件
echo "  复制二进制文件..."
sudo cp sslcat $TARGET_DIR/

# 复制 web 资源
if [ -d "web" ]; then
    echo "  复制 web 资源..."
    sudo cp -r web $TARGET_DIR/
fi

if [ -d "webapp" ]; then
    echo "  复制 webapp 资源..."
    sudo cp -r webapp $TARGET_DIR/
fi

# 复制前端构建文件
if [ -d "frontend/dist" ]; then
    echo "  复制前端构建文件..."
    sudo mkdir -p $TARGET_DIR/frontend
    sudo cp -r frontend/dist $TARGET_DIR/frontend/
fi

# 复制 i18n 文件
if [ -d "i18n" ]; then
    echo "  复制 i18n 文件..."
    sudo cp -r i18n $TARGET_DIR/
fi

# 复制脚本
if [ -d "scripts" ]; then
    echo "  复制脚本..."
    sudo cp -r scripts $TARGET_DIR/
    sudo chmod +x $TARGET_DIR/scripts/* 2>/dev/null || true
fi

# 如果没有配置文件，复制示例配置
if [ ! -f "$TARGET_DIR/sslcat.conf" ] && [ -f "sslcat.conf.example" ]; then
    echo "  复制配置文件..."
    sudo cp sslcat.conf.example $TARGET_DIR/sslcat.conf
fi

# 设置权限
echo "  设置权限..."
sudo chown -R $USER:$USER $TARGET_DIR
sudo chmod +x $TARGET_DIR/sslcat

# 给二进制文件添加网络绑定能力
echo ""
echo "🔑 设置网络绑定能力..."
sudo setcap 'cap_net_bind_service=+ep' $TARGET_DIR/sslcat
echo "  已授予 CAP_NET_BIND_SERVICE 权限"

# 创建 systemd 服务
echo ""
echo "📝 创建 systemd 服务..."
sudo tee /etc/systemd/system/sslcat.service > /dev/null << EOF
[Unit]
Description=SSLcat Reverse Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$TARGET_DIR
ExecStart=$TARGET_DIR/sslcat
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

# 安全设置
PrivateTmp=true
ProtectHome=false
ReadWritePaths=/opt/sslcat /etc/sslcat /opt/sslcat /home/git/

# 资源限制
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 重新加载 systemd
echo "  重新加载 systemd..."
sudo systemctl daemon-reload

# 启用并启动服务
echo ""
echo "🚀 启动服务..."
sudo systemctl enable sslcat
sudo systemctl start sslcat

# 等待服务启动
echo "  等待服务启动..."
sleep 3

# 检查服务状态
if sudo systemctl is-active --quiet sslcat; then
    echo "✅ 服务启动成功"
else
    echo "❌ 服务启动失败，查看日志："
    sudo journalctl -u sslcat -n 50 --no-pager
    exit 1
fi

echo ""
echo "=========================================="
echo "✅ 编译和部署完成！"
echo "=========================================="
echo ""
echo "📊 服务信息："
echo "  部署目录: $TARGET_DIR"
echo "  二进制文件: $TARGET_DIR/sslcat"
echo "  配置文件: $TARGET_DIR/sslcat.conf"
echo ""
echo "🔧 管理命令："
echo "  查看状态: sudo systemctl status sslcat"
echo "  查看日志: sudo journalctl -u sslcat -f"
echo "  重启服务: sudo systemctl restart sslcat"
echo "  停止服务: sudo systemctl stop sslcat"
echo ""

EOFSCRIPT

chmod +x $TEMP_SRC_DIR/server-build-and-deploy.sh

# 3. 上传源代码到服务器
echo ""
echo "📤 上传源代码到服务器..."
echo "  压缩源代码..."
cd $(dirname $TEMP_SRC_DIR)
tar czf sslcat-source.tar.gz $(basename $TEMP_SRC_DIR)

echo "  上传到服务器..."
scp sslcat-source.tar.gz $TARGET_USER@$TARGET_HOST:/tmp/

echo "  清理本地临时文件..."
rm -rf $TEMP_SRC_DIR
rm sslcat-source.tar.gz

# 4. 在服务器上解压并编译
echo ""
echo "🚀 在服务器上解压、编译和部署..."
ssh $TARGET_USER@$TARGET_HOST << 'EOFSSH'
set -e

echo "解压源代码..."
cd /tmp
rm -rf sslcat-source-deploy
tar xzf sslcat-source.tar.gz
cd sslcat-source-deploy

echo ""
echo "开始编译和部署..."
bash server-build-and-deploy.sh

echo ""
echo "清理临时文件..."
cd /tmp
rm -rf sslcat-source-deploy
rm sslcat-source.tar.gz

EOFSSH

echo ""
echo "==============================================="
echo "✅ 部署完成！"
echo "==============================================="
echo ""
echo "📊 服务信息："
echo "  服务器: $TARGET_USER@$TARGET_HOST"
echo "  部署目录: $TARGET_DIR"
echo "  管理面板: https://shifen.de/sslcat-panel/"
echo ""
echo "🔧 远程管理命令："
echo "  查看状态: ssh $TARGET_USER@$TARGET_HOST 'sudo systemctl status sslcat'"
echo "  查看日志: ssh $TARGET_USER@$TARGET_HOST 'sudo journalctl -u sslcat -f'"
echo "  重启服务: ssh $TARGET_USER@$TARGET_HOST 'sudo systemctl restart sslcat'"
echo ""
echo "📝 后续配置："
echo "  1. 编辑配置: ssh $TARGET_USER@$TARGET_HOST 'sudo nano $TARGET_DIR/sslcat.conf'"
echo "  2. 重启服务以应用配置更改"
echo "  3. 确保防火墙开放 443 端口（HTTPS）"
echo ""

