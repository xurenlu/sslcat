#!/bin/bash

# shifen.de CPU/内存飙升快速修复脚本
# 用途: 封禁攻击IP、检查配置、重启服务

set -e

SERVER="rocky@shifen.de"
ATTACKER_IP="34.74.55.33"

echo "========================================="
echo "shifen.de sslcat 紧急修复脚本"
echo "========================================="
echo ""

# 1. 封禁攻击 IP
echo "[1/5] 封禁攻击 IP: $ATTACKER_IP"
ssh $SERVER "sudo iptables -C INPUT -s $ATTACKER_IP -j DROP 2>/dev/null || sudo iptables -A INPUT -s $ATTACKER_IP -j DROP"
echo "✓ 攻击 IP 已封禁"
echo ""

# 2. 保存 iptables 规则
echo "[2/5] 保存 iptables 规则"
ssh $SERVER "sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null" || echo "⚠ 无法保存 iptables 规则 (可能需要手动保存)"
echo "✓ iptables 规则已保存"
echo ""

# 3. 检查 gg.some.im 配置
echo "[3/5] 检查 gg.some.im 配置"
echo "当前配置:"
ssh $SERVER "cat /etc/sslcat/sslcat.conf | grep -A 5 'gg.some.im' || echo '未找到 gg.some.im 配置'"
echo ""

# 4. 检查后端服务状态
echo "[4/5] 检查后端服务 (127.0.0.1:80)"
ssh $SERVER "sudo netstat -tlnp | grep ':80 ' || echo '⚠ 端口 80 没有服务监听'"
echo ""

# 5. 询问是否重启 sslcat
echo "[5/5] 重启 sslcat 服务"
read -p "是否立即重启 sslcat 服务以清理泄漏的 goroutine? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "正在重启 sslcat..."
    ssh $SERVER "sudo systemctl restart sslcat"
    echo "✓ sslcat 已重启"
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    echo ""
    echo "服务状态:"
    ssh $SERVER "sudo systemctl status sslcat --no-pager | head -20"
    
    # 检查资源使用
    echo ""
    echo "资源使用情况:"
    ssh $SERVER "ps aux | grep sslcat | grep -v grep"
else
    echo "⚠ 跳过重启。建议稍后手动重启: sudo systemctl restart sslcat"
fi

echo ""
echo "========================================="
echo "修复完成!"
echo "========================================="
echo ""
echo "后续建议:"
echo "1. 监控 CPU 和内存使用情况"
echo "2. 检查 /var/log/syslog 或 journalctl -u sslcat -f"
echo "3. 如果 gg.some.im 不再使用，请从配置中删除"
echo "4. 考虑添加 WAF 规则防止类似扫描"
echo ""
echo "详细诊断报告: SHIFEN_CPU_MEMORY_SPIKE_DIAGNOSIS.md"

