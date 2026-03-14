#!/bin/bash
# 安装 sslcat-git-hook wrapper 脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_PATH="/usr/local/bin/sslcat-git-hook"

echo "=========================================="
echo "安装 SSLcat Git Hook Wrapper"
echo "=========================================="
echo ""

# 检查是否以 root 权限运行
if [[ $EUID -ne 0 ]]; then
   echo "错误: 此脚本需要 root 权限运行"
   echo "请使用: sudo $0"
   exit 1
fi

# 复制脚本到系统路径
echo "📋 复制 sslcat-git-hook 到 $TARGET_PATH..."
cp "$SCRIPT_DIR/sslcat-git-hook" "$TARGET_PATH"
chmod +x "$TARGET_PATH"

echo "✅ sslcat-git-hook 已安装到: $TARGET_PATH"
echo ""

# 创建配置文件（如果不存在）
CONFIG_DIR="/etc/sslcat"
CONFIG_FILE="$CONFIG_DIR/git-hook.conf"

echo "📋 检测 SSLcat 配置..."

# 检查 jq 是否安装，如果没有则尝试安装
if ! command -v jq >/dev/null 2>&1; then
    echo "⚠️  未检测到 jq，正在尝试安装..."
    
    # 检测系统类型并安装 jq
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        apt-get update -qq && apt-get install -y -qq jq
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL
        yum install -y -q jq
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora
        dnf install -y -q jq
    elif command -v brew >/dev/null 2>&1; then
        # macOS
        brew install jq
    else
        echo "  ❌ 无法自动安装 jq，将使用 grep 降级方案（可能不够准确）"
        echo "  💡 建议手动安装 jq 以获得更好的配置检测："
        echo "     Debian/Ubuntu: apt-get install jq"
        echo "     CentOS/RHEL:   yum install jq"
        echo "     macOS:         brew install jq"
        echo ""
    fi
fi

# 尝试自动检测配置
DETECTED_ADMIN_PREFIX=""
DETECTED_PORT=""
DETECTED_REPOS_DIR=""

# 查找 sslcat 配置文件的常见位置
for conf_path in "/etc/sslcat/sslcat.conf" "$SCRIPT_DIR/../sslcat.conf" "$SCRIPT_DIR/../data/sslcat.conf"; do
    if [[ -f "$conf_path" ]]; then
        echo "  找到配置文件: $conf_path"
        # 使用 jq 或 grep 提取配置
        if command -v jq >/dev/null 2>&1; then
            echo "  ✓ 使用 jq 解析配置"
            DETECTED_ADMIN_PREFIX=$(jq -r '.admin_prefix // empty' "$conf_path" 2>/dev/null || echo "")
            DETECTED_PORT=$(jq -r '.server.port // empty' "$conf_path" 2>/dev/null || echo "")
            DETECTED_REPOS_DIR=$(jq -r '.runners.git.repos_dir // empty' "$conf_path" 2>/dev/null || echo "")
        else
            # 如果没有 jq，尝试用 grep 提取（不太精确）
            echo "  ⚠️  使用 grep 降级方案（可能不够准确）"
            DETECTED_ADMIN_PREFIX=$(grep -o '"admin_prefix"[[:space:]]*:[[:space:]]*"[^"]*"' "$conf_path" | sed 's/.*"\([^"]*\)".*/\1/' | head -1 || echo "")
            DETECTED_PORT=$(grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' "$conf_path" | grep -o '[0-9]*' | head -1 || echo "")
            DETECTED_REPOS_DIR=$(grep -o '"repos_dir"[[:space:]]*:[[:space:]]*"[^"]*"' "$conf_path" | sed 's/.*"\([^"]*\)".*/\1/' | head -1 || echo "")
        fi
        break
    fi
done

# 设置默认值
ADMIN_PREFIX="${DETECTED_ADMIN_PREFIX:-/sslcat-panel2}"
SERVER_PORT="${DETECTED_PORT:-9942}"
REPOS_DIR="${DETECTED_REPOS_DIR:-/opt/sslcat/data/runners/git}"

# 智能构建 API URL
# 当端口为 443 时，使用 HTTP (80) 进行 API 调用，因为 443 是 HTTPS 端口
if [[ "$SERVER_PORT" == "443" ]]; then
    API_URL="http://127.0.0.1:80${ADMIN_PREFIX}"
    echo "  ⚠️  检测到端口 443，使用 HTTP (80) 进行 API 调用"
else
    API_URL="http://127.0.0.1:${SERVER_PORT}${ADMIN_PREFIX}"
fi

echo "  检测到的配置："
echo "    Admin Prefix: $ADMIN_PREFIX"
echo "    Server Port:  $SERVER_PORT"
echo "    Repos Dir:    $REPOS_DIR"
echo "    API URL:      $API_URL"
echo ""

echo "📋 创建配置文件..."
if [[ ! -f "$CONFIG_FILE" ]]; then
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# SSLcat Git Hook 配置文件
# 自动生成于: $(date)
# 
# 此配置从 SSLcat 主配置文件自动检测而来
# 如果 SSLcat 配置变更，请重新运行安装脚本或手动修改此文件

# SSLcat API 地址
export SSLCAT_API_URL="$API_URL"

# Git 仓库存储目录
export SSLCAT_REPOS_DIR="$REPOS_DIR"

# 注意：如果修改了 SSLcat 的 admin_prefix 或端口，需要同步更新此文件
EOF
    chmod 644 "$CONFIG_FILE"
    echo "✅ 配置文件已创建: $CONFIG_FILE"
else
    echo "ℹ️  配置文件已存在: $CONFIG_FILE"
    echo ""
    echo "⚠️  检测到配置文件已存在，新配置为："
    echo "    $API_URL"
    echo ""
    read -p "是否要更新配置文件? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > "$CONFIG_FILE" << EOF
# SSLcat Git Hook 配置文件
# 更新于: $(date)

# SSLcat API 地址
export SSLCAT_API_URL="$API_URL"

# Git 仓库存储目录
export SSLCAT_REPOS_DIR="$REPOS_DIR"
EOF
        echo "✅ 配置文件已更新"
    else
        echo "ℹ️  保持现有配置不变"
    fi
fi
echo ""

# 设置环境变量（可选）
echo "📝 配置说明："
echo ""
echo "可以通过以下环境变量自定义配置："
echo "  SSLCAT_API_URL     - SSLcat API 地址（默认: http://127.0.0.1/sslcat-panel）"
echo "  SSLCAT_REPOS_DIR   - Git 仓库目录（默认: /opt/sslcat/data/runners/git）"
echo ""
echo "要设置环境变量，编辑 git 用户的配置："
echo "  sudo -u git nano ~/.bashrc"
echo ""
echo "添加："
echo "  export SSLCAT_API_URL='http://127.0.0.1/sslcat-panel'"
echo "  export SSLCAT_REPOS_DIR='/opt/sslcat/data/runners/git'"
echo ""

# 验证安装
echo "🔍 验证安装..."
if [[ -x "$TARGET_PATH" ]]; then
    echo "✅ 安装成功！"
    echo ""
    echo "现在可以添加 SSH 密钥了，新密钥将自动使用 Dokku 风格。"
    echo "git push 时会自动创建不存在的应用！"
else
    echo "❌ 安装失败"
    exit 1
fi

echo ""
echo "=========================================="
echo "安装完成！"
echo "=========================================="

