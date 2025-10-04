#!/bin/bash
# 检查 Git 应用 "p" 的完整状态

echo "=========================================="
echo "检查 Git 应用 'p' 的状态"
echo "=========================================="
echo ""

APP_NAME="p"
REPOS_DIR="/opt/sslcat/data/runners/git"
APP_DIR="$REPOS_DIR/$APP_NAME"
BARE_REPO="$APP_DIR/git/repo.git"
SYMLINK="/home/git/$APP_NAME.git"
AUTHORIZED_KEYS="/home/git/.ssh/authorized_keys"

# 1. 检查应用目录
echo "1️⃣  检查应用目录"
if [ -d "$APP_DIR" ]; then
    echo "   ✅ 应用目录存在: $APP_DIR"
    ls -la "$APP_DIR"
else
    echo "   ❌ 应用目录不存在: $APP_DIR"
fi
echo ""

# 2. 检查 Git 裸仓库
echo "2️⃣  检查 Git 裸仓库"
if [ -d "$BARE_REPO" ]; then
    echo "   ✅ 裸仓库存在: $BARE_REPO"
    ls -la "$BARE_REPO"
    echo ""
    # 检查是否是有效的 Git 仓库
    if [ -f "$BARE_REPO/HEAD" ]; then
        echo "   ✅ 是有效的 Git 仓库（HEAD 文件存在）"
    else
        echo "   ❌ 不是有效的 Git 仓库（HEAD 文件不存在）"
    fi
else
    echo "   ❌ 裸仓库不存在: $BARE_REPO"
fi
echo ""

# 3. 检查符号链接
echo "3️⃣  检查符号链接"
if [ -L "$SYMLINK" ]; then
    TARGET=$(readlink "$SYMLINK")
    echo "   ✅ 符号链接存在: $SYMLINK"
    echo "   → 指向: $TARGET"
    if [ -d "$TARGET" ]; then
        echo "   ✅ 目标路径存在"
    else
        echo "   ❌ 目标路径不存在"
    fi
else
    echo "   ❌ 符号链接不存在: $SYMLINK"
fi
echo ""

# 4. 检查 SSH 密钥
echo "4️⃣  检查 SSH 密钥"
if [ -f "$AUTHORIZED_KEYS" ]; then
    echo "   ✅ authorized_keys 文件存在: $AUTHORIZED_KEYS"
    KEY_COUNT=$(grep -c "^ssh-" "$AUTHORIZED_KEYS" 2>/dev/null || echo 0)
    echo "   📝 包含 $KEY_COUNT 个密钥"
    if [ $KEY_COUNT -eq 0 ]; then
        echo "   ⚠️  没有任何 SSH 密钥，无法推送"
    fi
else
    echo "   ❌ authorized_keys 文件不存在: $AUTHORIZED_KEYS"
fi
echo ""

# 5. 检查 git 用户
echo "5️⃣  检查 git 用户"
if id git >/dev/null 2>&1; then
    echo "   ✅ git 用户存在"
    echo "   $(getent passwd git)"
else
    echo "   ❌ git 用户不存在"
fi
echo ""

# 6. 给出诊断建议
echo "=========================================="
echo "📋 诊断建议"
echo "=========================================="

if [ ! -d "$BARE_REPO" ] || [ ! -f "$BARE_REPO/HEAD" ]; then
    echo "❌ Git 裸仓库问题："
    echo "   需要手动初始化仓库："
    echo "   cd $APP_DIR/git"
    echo "   git init --bare repo.git"
    echo ""
fi

if [ ! -L "$SYMLINK" ]; then
    echo "❌ 符号链接问题："
    echo "   需要手动创建符号链接："
    echo "   ln -s $BARE_REPO $SYMLINK"
    echo "   chown -h git:git $SYMLINK"
    echo ""
fi

if [ ! -f "$AUTHORIZED_KEYS" ] || [ $(grep -c "^ssh-" "$AUTHORIZED_KEYS" 2>/dev/null || echo 0) -eq 0 ]; then
    echo "❌ SSH 密钥问题："
    echo "   需要添加 SSH 公钥："
    echo "   通过 Web 界面添加，或者手动编辑："
    echo "   echo 'ssh-rsa AAAA...' >> $AUTHORIZED_KEYS"
    echo "   chmod 600 $AUTHORIZED_KEYS"
    echo "   chown git:git $AUTHORIZED_KEYS"
    echo ""
fi

echo "✅ 检查完成！"

