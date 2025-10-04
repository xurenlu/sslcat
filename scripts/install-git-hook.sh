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

# 设置环境变量（可选）
echo "📝 配置说明："
echo ""
echo "可以通过以下环境变量自定义配置："
echo "  SSLCAT_API_URL     - SSLcat API 地址（默认: http://localhost/sslcat-panel）"
echo "  SSLCAT_REPOS_DIR   - Git 仓库目录（默认: /opt/sslcat/data/runners/git）"
echo ""
echo "要设置环境变量，编辑 git 用户的配置："
echo "  sudo -u git nano ~/.bashrc"
echo ""
echo "添加："
echo "  export SSLCAT_API_URL='http://localhost/sslcat-panel'"
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

