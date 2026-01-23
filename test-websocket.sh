#!/bin/bash

# WebSocket 测试脚本
# 用于测试 sslcat 的 WebSocket 代理功能

set -e

echo "=========================================="
echo "WebSocket 测试脚本"
echo "=========================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试函数
test_websocket() {
    local protocol=$1
    local host=$2
    local port=$3
    local path=$4
    local name=$5
    
    echo -e "${YELLOW}测试 ${name}:${NC} ${protocol}://${host}:${port}${path}"
    
    # 使用 curl 测试 WebSocket 升级请求
    response=$(curl -s -w "\n%{http_code}" \
        --http1.1 \
        -H "Connection: Upgrade" \
        -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        "${protocol}://${host}:${port}${path}" 2>&1 || echo "连接失败")
    
    http_code=$(echo "$response" | tail -n 1)
    
    if [ "$http_code" = "101" ]; then
        echo -e "  ${GREEN}✓ WebSocket 升级成功 (HTTP 101)${NC}"
        return 0
    else
        echo -e "  ${RED}✗ WebSocket 升级失败 (HTTP ${http_code})${NC}"
        echo "  响应内容:"
        echo "$response" | head -n -1 | sed 's/^/    /'
        return 1
    fi
}

# 检查配置文件
if [ ! -f "sslcat.conf" ]; then
    echo -e "${RED}错误: 找不到 sslcat.conf 配置文件${NC}"
    exit 1
fi

echo "1. 检查配置文件..."
echo "   配置文件: sslcat.conf"
echo ""

# 提取代理配置
proxy_domains=$(grep -o '"domain": *"[^"]*"' sslcat.conf | cut -d'"' -f4 || echo "")

if [ -z "$proxy_domains" ]; then
    echo -e "${RED}错误: 配置文件中没有找到代理规则${NC}"
    exit 1
fi

echo "2. 发现的代理域名:"
echo "$proxy_domains" | sed 's/^/   - /'
echo ""

# 获取 sslcat 监听的端口
sslcat_port=$(ps aux | grep '[s]slcat' | grep -oP '\-\-port[= ]\K\d+' | head -1)
if [ -z "$sslcat_port" ]; then
    sslcat_port="8080"  # 默认端口
fi

echo "3. sslcat 监听端口: ${sslcat_port}"
echo ""

# 测试每个域名的 WebSocket 连接
echo "4. 开始测试 WebSocket 连接..."
echo ""

success_count=0
fail_count=0

for domain in $proxy_domains; do
    # 测试 HTTP WebSocket (如果 sslcat 监听在非标准端口)
    if test_websocket "http" "$domain" "$sslcat_port" "/" "HTTP WebSocket"; then
        ((success_count++))
    else
        ((fail_count++))
    fi
    echo ""
    
    # 测试 HTTPS WebSocket (如果配置了 SSL)
    if grep -q '"enable_https": *true' sslcat.conf; then
        if test_websocket "https" "$domain" "443" "/" "HTTPS WebSocket"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
        echo ""
    fi
done

# 测试结果汇总
echo "=========================================="
echo "测试结果汇总"
echo "=========================================="
echo -e "成功: ${GREEN}${success_count}${NC}"
echo -e "失败: ${RED}${fail_count}${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过!${NC}"
    exit 0
else
    echo -e "${RED}✗ 部分测试失败，请检查日志${NC}"
    echo ""
    echo "调试建议:"
    echo "1. 检查 sslcat 日志:"
    echo "   tail -f /var/log/sslcat/sslcat.log"
    echo ""
    echo "2. 启用 debug 日志:"
    echo "   sslcat -log-level debug"
    echo ""
    echo "3. 检查后端服务是否正常:"
    echo "   nc -zv <backend-host> <backend-port>"
    echo ""
    echo "4. 使用 tcpdump 抓包:"
    echo "   sudo tcpdump -i any port <backend-port> -w websocket.pcap"
    exit 1
fi
