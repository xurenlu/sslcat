#!/bin/bash
# 配置热重载通知功能测试脚本

set -e

echo "==================================="
echo "配置热重载通知功能测试"
echo "==================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否有配置文件
if [ ! -f "sslcat.conf" ]; then
    echo -e "${RED}错误: 找不到 sslcat.conf 文件${NC}"
    echo "请先创建配置文件或使用 sslcat-notification-test.conf.example"
    exit 1
fi

# 备份原配置
echo -e "${YELLOW}1. 备份原配置文件...${NC}"
BACKUP_FILE="sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)"
cp sslcat.conf "$BACKUP_FILE"
echo -e "${GREEN}✓ 已备份到: $BACKUP_FILE${NC}"
echo ""

# 验证配置语法
echo -e "${YELLOW}2. 验证配置文件语法...${NC}"
if python3 -m json.tool sslcat.conf > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 配置文件语法正确${NC}"
else
    echo -e "${RED}✗ 配置文件语法错误${NC}"
    echo "请修复配置文件后再运行测试"
    exit 1
fi
echo ""

# 测试说明
echo -e "${YELLOW}3. 测试步骤:${NC}"
echo ""
echo "请按照以下步骤测试配置热重载通知功能："
echo ""
echo "步骤 1: 启动 SSLcat"
echo "  ./sslcat --config sslcat.conf"
echo ""
echo "步骤 2: 在另一个终端修改配置文件"
echo "  nano sslcat.conf"
echo "  # 修改一个代理规则或添加新规则"
echo ""
echo "步骤 3: 保存配置文件并等待 1-2 秒"
echo ""
echo "步骤 4: 查看 SSLcat 日志输出"
echo "  应该看到类似以下内容："
echo "  - INFO Configuration changed, starting hot reload..."
echo "  - INFO Configuration reload started"
echo "  - INFO Configuration reload completed successfully in XXms"
echo "  - INFO 通知已发送: config_reloaded - 配置文件热重载成功"
echo ""
echo "步骤 5: 检查通知渠道"
echo "  - 控制台: 查看终端输出"
echo "  - 邮件: 检查配置的邮箱"
echo "  - Webhook: 检查 webhook 接收端"
echo ""
echo "步骤 6: 测试配置错误场景"
echo "  nano sslcat.conf"
echo "  # 故意引入 JSON 语法错误（删除一个逗号）"
echo "  # 保存后应该看到错误通知"
echo ""
echo "步骤 7: 恢复配置"
echo "  # 修复语法错误或使用备份恢复"
echo "  cp $BACKUP_FILE sslcat.conf"
echo ""

# 询问是否继续
echo -e "${YELLOW}是否现在开始测试? (y/n)${NC}"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo ""
    echo -e "${GREEN}正在启动 SSLcat...${NC}"
    echo -e "${YELLOW}提示: 使用 Ctrl+C 停止服务${NC}"
    echo ""
    sleep 2
    
    # 启动 SSLcat
    ./sslcat --config sslcat.conf
else
    echo ""
    echo -e "${YELLOW}测试已取消${NC}"
    echo -e "配置文件已备份到: ${GREEN}$BACKUP_FILE${NC}"
    echo ""
fi

