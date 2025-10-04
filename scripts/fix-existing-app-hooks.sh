#!/bin/bash
# 修复现有应用的 Git hooks
# 用法: ./fix-existing-app-hooks.sh <应用名称>

set -e

APP_NAME="$1"
if [ -z "$APP_NAME" ]; then
    echo "用法: $0 <应用名称>"
    echo "示例: $0 p"
    exit 1
fi

echo "正在修复应用 $APP_NAME 的 Git hooks..."

# 尝试多个可能的仓库位置
BARE_REPO=""
if [ -d "/home/git/${APP_NAME}.git" ]; then
    BARE_REPO="/home/git/${APP_NAME}.git"
    echo "✓ 找到仓库: $BARE_REPO"
elif [ -d "/opt/sslcat/data/runners/git/${APP_NAME}/git/repo.git" ]; then
    BARE_REPO="/opt/sslcat/data/runners/git/${APP_NAME}/git/repo.git"
    echo "✓ 找到仓库: $BARE_REPO"
else
    echo "✗ 错误: 找不到应用 $APP_NAME 的 Git 仓库"
    echo "  已尝试:"
    echo "    - /home/git/${APP_NAME}.git"
    echo "    - /opt/sslcat/data/runners/git/${APP_NAME}/git/repo.git"
    exit 1
fi

# 创建 hooks 目录
HOOKS_DIR="$BARE_REPO/hooks"
mkdir -p "$HOOKS_DIR"

# 创建 post-receive hook
echo "正在创建 post-receive hook..."
cat > "$HOOKS_DIR/post-receive" << 'EOF'
#!/bin/bash
# SSLcat Git Post-Receive Hook
# 自动触发部署

set -e

# 获取应用名称
if [[ "$(pwd)" =~ /home/git/(.+)\.git ]]; then
    APP_NAME="${BASH_REMATCH[1]}"
elif [[ "$(pwd)" =~ /git/([^/]+)/git/repo\.git ]]; then
    APP_NAME="${BASH_REMATCH[1]}"
else
    APP_NAME="$(basename $(pwd) .git)"
fi

# SSLcat API 配置
SSLCAT_API_URL="${SSLCAT_API_URL:-http://localhost/sslcat-panel}"

# 颜色定义
COLOR_RESET='\033[0m'
COLOR_BOLD='\033[1m'
COLOR_GREEN='\033[0;32m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
COLOR_RED='\033[0;31m'

echo ""
echo -e "${COLOR_BOLD}${COLOR_BLUE}╔═══════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_BOLD}${COLOR_BLUE}║${COLOR_RESET}     ${COLOR_BOLD}SSLcat Git Deploy${COLOR_RESET}           ${COLOR_BOLD}${COLOR_BLUE}║${COLOR_RESET}"
echo -e "${COLOR_BOLD}${COLOR_BLUE}╚═══════════════════════════════════════╝${COLOR_RESET}"
echo ""

# 从 stdin 读取推送信息
while read oldrev newrev refname; do
    # 获取提交信息
    if [ "$oldrev" != "0000000000000000000000000000000000000000" ]; then
        COMMIT_MSG=$(git rev-parse --short $newrev 2>/dev/null || echo "unknown")
        COMMIT_AUTHOR=$(git log -1 --pretty=format:"%an" $newrev 2>/dev/null || echo "Unknown")
    else
        COMMIT_MSG="Initial commit"
        COMMIT_AUTHOR="Unknown"
    fi
    
    echo -e "${COLOR_CYAN}Application:${COLOR_RESET} ${COLOR_BOLD}$APP_NAME${COLOR_RESET}"
    echo -e "${COLOR_CYAN}Commit:${COLOR_RESET}      $COMMIT_MSG"
    echo -e "${COLOR_CYAN}Author:${COLOR_RESET}      $COMMIT_AUTHOR"
    echo -e "${COLOR_CYAN}Branch:${COLOR_RESET}      ${refname##refs/heads/}"
    echo ""
    
    echo -e "${COLOR_GREEN}-----> 触发部署...${COLOR_RESET}"
    
    # 通过 API 触发部署
    RESPONSE=$(curl -s -X POST "$SSLCAT_API_URL/api/git-server/apps/${APP_NAME}/deploy" \
        -H "Content-Type: application/json" \
        -H "User-Agent: SSLcat-Git-Hook/1.0 (Internal)" \
        -d "{\"commit\":\"$newrev\",\"ref\":\"$refname\",\"message\":\"$COMMIT_MSG\"}" 2>&1)
    
    if echo "$RESPONSE" | grep -q '"success":true'; then
        echo -e "${COLOR_GREEN}-----> ✓ 部署已触发${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_CYAN}查看实时日志:${COLOR_RESET}"
        echo -e "  ${SSLCAT_API_URL}/git-deploy"
        echo ""
    else
        echo -e "${COLOR_RED}-----> ✗ 触发部署失败${COLOR_RESET}"
        echo -e "${COLOR_RED}API 响应: $RESPONSE${COLOR_RESET}"
    fi
done

echo -e "${COLOR_BOLD}${COLOR_GREEN}✓ Push 完成${COLOR_RESET}"
echo ""

exit 0
EOF

chmod +x "$HOOKS_DIR/post-receive"
chown -R git:git "$HOOKS_DIR" 2>/dev/null || true

echo "✓ post-receive hook 已创建: $HOOKS_DIR/post-receive"
echo ""
echo "现在可以测试 git push 了！"

