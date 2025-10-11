#!/bin/bash

# Access Log 快速修复脚本

echo "======================================"
echo "  SSLcat Access Log 快速修复工具"
echo "======================================"
echo ""

# 颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 查找配置文件
CONFIG_FILE=""
if [ -f "./sslcat.conf" ]; then
    CONFIG_FILE="./sslcat.conf"
elif [ -f "/etc/sslcat/sslcat.conf" ]; then
    CONFIG_FILE="/etc/sslcat/sslcat.conf"
else
    echo "❌ 未找到配置文件"
    echo "请指定配置文件路径: $0 /path/to/sslcat.conf"
    exit 1
fi

if [ -n "$1" ] && [ -f "$1" ]; then
    CONFIG_FILE="$1"
fi

echo "使用配置文件: $CONFIG_FILE"
echo ""

# 备份配置文件
BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$CONFIG_FILE" "$BACKUP_FILE"
echo -e "${GREEN}✓${NC} 配置文件已备份到: $BACKUP_FILE"
echo ""

# 检查并修复配置
echo "检查配置..."
NEED_FIX=0

# 检查 access_log_enabled
if ! grep -q '"access_log_enabled"' "$CONFIG_FILE"; then
    echo -e "${YELLOW}⚠${NC} 未找到 access_log_enabled，将添加"
    NEED_FIX=1
elif grep -q '"access_log_enabled"[[:space:]]*:[[:space:]]*false' "$CONFIG_FILE"; then
    echo -e "${YELLOW}⚠${NC} access_log_enabled 为 false，将改为 true"
    NEED_FIX=1
fi

# 检查 access_log_path
if ! grep -q '"access_log_path"' "$CONFIG_FILE"; then
    echo -e "${YELLOW}⚠${NC} 未找到 access_log_path，将添加"
    NEED_FIX=1
elif grep -q '"access_log_path"[[:space:]]*:[[:space:]]*""' "$CONFIG_FILE"; then
    echo -e "${YELLOW}⚠${NC} access_log_path 为空，将设置为 ./data/access.log"
    NEED_FIX=1
fi

if [ $NEED_FIX -eq 0 ]; then
    echo -e "${GREEN}✓${NC} 配置看起来正确"
    echo ""
else
    echo ""
    echo "修复配置..."
    
    # 使用 Python 或 jq 来修改 JSON（如果可用）
    if command -v jq &> /dev/null; then
        # 使用 jq
        jq '.server.access_log_enabled = true | 
            .server.access_log_path = (if .server.access_log_path == "" or .server.access_log_path == null then "./data/access.log" else .server.access_log_path end) |
            .server.access_log_format = (if .server.access_log_format == "" or .server.access_log_format == null then "nginx" else .server.access_log_format end)' \
            "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
        
        if [ $? -eq 0 ]; then
            mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            echo -e "${GREEN}✓${NC} 配置文件已更新"
        else
            echo "❌ jq 处理失败，尝试手动修改..."
            rm -f "${CONFIG_FILE}.tmp"
            
            # 手动修改
            sed -i.bak 's/"access_log_enabled"[[:space:]]*:[[:space:]]*false/"access_log_enabled": true/' "$CONFIG_FILE"
            sed -i.bak 's/"access_log_path"[[:space:]]*:[[:space:]]*""/"access_log_path": ".\/data\/access.log"/' "$CONFIG_FILE"
            echo -e "${GREEN}✓${NC} 配置文件已更新（使用 sed）"
        fi
    else
        # 没有 jq，使用 sed
        echo "使用 sed 修改配置..."
        sed -i.bak 's/"access_log_enabled"[[:space:]]*:[[:space:]]*false/"access_log_enabled": true/' "$CONFIG_FILE"
        
        # 如果没有 access_log_path，需要手动添加
        if ! grep -q '"access_log_path"' "$CONFIG_FILE"; then
            echo ""
            echo -e "${YELLOW}⚠${NC} 无法自动添加 access_log_path"
            echo "请手动编辑配置文件，在 server 部分添加："
            echo '  "access_log_enabled": true,'
            echo '  "access_log_path": "./data/access.log",'
            echo '  "access_log_format": "nginx"'
            echo ""
            echo "然后运行: systemctl restart sslcat"
            exit 1
        fi
        
        echo -e "${GREEN}✓${NC} 配置文件已更新"
    fi
fi

echo ""

# 创建日志目录
echo "创建日志目录..."
LOG_PATH=$(grep -o '"access_log_path"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*"//' | tr -d '"')

if [[ "$LOG_PATH" == /* ]]; then
    LOG_DIR=$(dirname "$LOG_PATH")
else
    LOG_DIR="./$(dirname "$LOG_PATH")"
fi

if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    echo -e "${GREEN}✓${NC} 创建目录: $LOG_DIR"
else
    echo -e "${GREEN}✓${NC} 目录已存在: $LOG_DIR"
fi

# 设置权限
chmod 755 "$LOG_DIR"
echo -e "${GREEN}✓${NC} 设置目录权限: 755"
echo ""

# 显示修改后的配置
echo "当前 Access Log 配置:"
echo "-----------------------------------"
grep -A 3 '"access_log' "$CONFIG_FILE" | grep -v '^--$'
echo "-----------------------------------"
echo ""

# 询问是否重启
echo "配置已更新！"
echo ""
echo "⚠️  需要重启服务才能生效"
echo ""
read -p "是否立即重启 SSLcat 服务？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "重启服务..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl restart sslcat
        echo -e "${GREEN}✓${NC} 服务已重启"
        
        # 等待几秒
        sleep 3
        
        # 发送测试请求
        echo ""
        echo "发送测试请求..."
        curl -s http://localhost/ > /dev/null
        sleep 1
        
        # 检查日志
        if [ -f "$LOG_PATH" ] || [ -f "$LOG_DIR/access.log" ]; then
            echo -e "${GREEN}✓${NC} 日志文件已创建"
            echo ""
            echo "最新日志:"
            tail -3 "$LOG_DIR"/*.log 2>/dev/null
        else
            echo -e "${YELLOW}⚠${NC} 日志文件尚未创建，请稍等或查看系统日志"
        fi
    else
        echo "请手动重启服务"
    fi
else
    echo ""
    echo "请稍后手动重启服务:"
    echo "  systemctl restart sslcat"
    echo ""
    echo "或者:"
    echo "  killall sslcat && ./sslcat &"
fi

echo ""
echo "完成！"

