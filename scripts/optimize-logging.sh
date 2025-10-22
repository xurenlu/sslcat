#!/bin/bash

# SSLCat 日志优化脚本
# 用于快速优化日志配置以减少 CPU 使用

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  SSLCat 日志与性能优化脚本${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# 检查配置文件位置
CONFIG_FILE=""
if [ -f "/etc/sslcat/sslcat.conf" ]; then
    CONFIG_FILE="/etc/sslcat/sslcat.conf"
elif [ -f "$PROJECT_ROOT/data/sslcat.conf" ]; then
    CONFIG_FILE="$PROJECT_ROOT/data/sslcat.conf"
elif [ -f "$PROJECT_ROOT/sslcat.conf" ]; then
    CONFIG_FILE="$PROJECT_ROOT/sslcat.conf"
else
    echo -e "${RED}错误：找不到配置文件${NC}"
    echo "请指定配置文件路径："
    read -p "配置文件路径: " CONFIG_FILE
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}错误：配置文件不存在${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}找到配置文件：${NC}$CONFIG_FILE"
echo ""

# 备份配置文件
BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo -e "${YELLOW}备份配置文件到：${NC}$BACKUP_FILE"
cp "$CONFIG_FILE" "$BACKUP_FILE"
echo ""

# 显示当前配置
echo -e "${YELLOW}当前日志配置：${NC}"
grep -A 5 '"logging"' "$CONFIG_FILE" || echo "无法读取日志配置"
echo ""

# 询问用户选择优化级别
echo -e "${YELLOW}请选择优化级别：${NC}"
echo "1) 温和优化 - 将日志级别改为 warn，保留访问日志"
echo "2) 标准优化 - 将日志级别改为 warn，禁用访问日志（推荐）"
echo "3) 激进优化 - 将日志级别改为 error，禁用访问日志"
echo "4) 自定义配置"
echo "5) 取消"
echo ""

read -p "请选择 [1-5]: " choice

case $choice in
    1)
        echo -e "${GREEN}应用温和优化...${NC}"
        # 使用 Python 或 jq 修改 JSON 配置
        if command -v jq &> /dev/null; then
            jq '.logging.level = "warn"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        else
            sed -i.bak 's/"level": *"info"/"level": "warn"/' "$CONFIG_FILE"
            sed -i.bak 's/"level": *"debug"/"level": "warn"/' "$CONFIG_FILE"
        fi
        echo -e "${GREEN}✓ 日志级别已设置为 warn${NC}"
        ;;
    
    2)
        echo -e "${GREEN}应用标准优化（推荐）...${NC}"
        if command -v jq &> /dev/null; then
            jq '.logging.level = "warn" | .logging.access_log_enabled = false' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        else
            # 使用 sed 修改
            sed -i.bak 's/"level": *"[^"]*"/"level": "warn"/' "$CONFIG_FILE"
            
            # 如果存在 access_log_enabled，修改它；否则添加
            if grep -q '"access_log_enabled"' "$CONFIG_FILE"; then
                sed -i.bak 's/"access_log_enabled": *true/"access_log_enabled": false/' "$CONFIG_FILE"
            else
                # 在 logging 部分添加 access_log_enabled
                sed -i.bak '/"logging":/,/}/ {
                    /"security_log":/a\    "access_log_enabled": false,
                }' "$CONFIG_FILE"
            fi
        fi
        echo -e "${GREEN}✓ 日志级别已设置为 warn${NC}"
        echo -e "${GREEN}✓ 访问日志已禁用${NC}"
        ;;
    
    3)
        echo -e "${GREEN}应用激进优化...${NC}"
        if command -v jq &> /dev/null; then
            jq '.logging.level = "error" | .logging.access_log_enabled = false' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        else
            sed -i.bak 's/"level": *"[^"]*"/"level": "error"/' "$CONFIG_FILE"
            if grep -q '"access_log_enabled"' "$CONFIG_FILE"; then
                sed -i.bak 's/"access_log_enabled": *true/"access_log_enabled": false/' "$CONFIG_FILE"
            fi
        fi
        echo -e "${GREEN}✓ 日志级别已设置为 error${NC}"
        echo -e "${GREEN}✓ 访问日志已禁用${NC}"
        ;;
    
    4)
        echo -e "${YELLOW}自定义配置${NC}"
        read -p "日志级别 (debug/info/warn/error): " log_level
        read -p "启用访问日志? (yes/no): " enable_access_log
        
        if command -v jq &> /dev/null; then
            if [ "$enable_access_log" = "yes" ]; then
                jq ".logging.level = \"$log_level\" | .logging.access_log_enabled = true" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            else
                jq ".logging.level = \"$log_level\" | .logging.access_log_enabled = false" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            fi
        else
            sed -i.bak "s/\"level\": *\"[^\"]*\"/\"level\": \"$log_level\"/" "$CONFIG_FILE"
        fi
        echo -e "${GREEN}✓ 自定义配置已应用${NC}"
        ;;
    
    5)
        echo -e "${YELLOW}取消操作${NC}"
        exit 0
        ;;
    
    *)
        echo -e "${RED}无效选择${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${YELLOW}优化后的日志配置：${NC}"
grep -A 7 '"logging"' "$CONFIG_FILE" || echo "无法读取日志配置"
echo ""

# 询问是否重启服务
echo -e "${YELLOW}需要重启 sslcat 服务以应用配置${NC}"
read -p "是否立即重启服务? (yes/no): " restart

if [ "$restart" = "yes" ] || [ "$restart" = "y" ]; then
    echo ""
    echo -e "${GREEN}重启 sslcat 服务...${NC}"
    
    # 检测服务管理方式
    if systemctl is-active --quiet sslcat 2>/dev/null; then
        sudo systemctl restart sslcat
        echo -e "${GREEN}✓ sslcat 服务已重启（systemd）${NC}"
    elif pgrep -x sslcat > /dev/null; then
        # 尝试使用 kill 重启
        echo -e "${YELLOW}检测到 sslcat 进程，尝试重启...${NC}"
        pkill -HUP sslcat || true
        echo -e "${GREEN}✓ 已发送重启信号${NC}"
    else
        echo -e "${YELLOW}未检测到运行中的 sslcat 服务${NC}"
        echo "请手动启动服务：sudo systemctl start sslcat"
    fi
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  优化完成！${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${YELLOW}监控建议：${NC}"
echo "1. 查看日志输出："
echo "   journalctl -f -u sslcat"
echo ""
echo "2. 监控 CPU 使用："
echo "   top -p \$(pgrep sslcat)"
echo ""
echo "3. 测试静态资源速度："
echo "   curl -w \"@curl-format.txt\" -o /dev/null -s http://your-domain/sslcat-panel/assets/index-xxx.js"
echo ""
echo -e "${YELLOW}如需恢复原配置，请使用备份文件：${NC}"
echo "   cp $BACKUP_FILE $CONFIG_FILE"
echo ""
echo -e "${GREEN}详细文档：${NC}docs/LOGGING_AND_PERFORMANCE_OPTIMIZATION.md"
echo ""

