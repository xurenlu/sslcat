#!/bin/bash
# 测试 install-sslcat.sh 静默升级模式参数解析
# 不要求 root，仅验证 -s / --silent-upgrade 被正确识别
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_SCRIPT="$PROJECT_ROOT/install-sslcat.sh"

echo "🧪 测试 install-sslcat.sh 静默升级模式..."

# 1. 语法检查
bash -n "$INSTALL_SCRIPT" || { echo "❌ 语法错误"; exit 1; }
echo "✅ 语法检查通过"

# 2. 静默模式应跳过语言选择，直接输出 root 错误（无 "Select language" / "选择语言"）
output=$(cd "$PROJECT_ROOT" && bash "$INSTALL_SCRIPT" -s 2>&1) || true
if echo "$output" | grep -qE "Select language|选择语言"; then
    echo "❌ 静默模式不应显示语言选择"
    exit 1
fi
echo "✅ -s 参数生效，跳过语言选择"

# 3. --silent-upgrade 同样生效
output2=$(cd "$PROJECT_ROOT" && bash "$INSTALL_SCRIPT" --silent-upgrade 2>&1) || true
if echo "$output2" | grep -qE "Select language|选择语言"; then
    echo "❌ --silent-upgrade 模式下不应显示语言选择"
    exit 1
fi
echo "✅ --silent-upgrade 参数生效"

echo ""
echo "✅ 静默升级模式测试通过"
