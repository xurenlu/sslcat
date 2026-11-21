#!/bin/bash
set -e

# 快速修复 shifen.de 服务器的 CPU 问题
# 通过环境变量调整 GOGC 参数

SERVER="rocky@shifen.de"

echo "=== 快速修复 shifen.de CPU 高占用问题 ==="
echo ""

# 1. 检查当前状态
echo "[1/4] 检查当前 CPU 使用情况..."
ssh $SERVER "ps aux | grep -E 'PID|sslcat' | grep -v grep"
echo ""

# 2. 修改 systemd 服务配置，添加 GOGC 环境变量
echo "[2/4] 修改 systemd 服务配置..."
ssh $SERVER "sudo bash -c 'cat > /tmp/sslcat-env.conf << EOF
[Service]
Environment=\"GOGC=100\"
Environment=\"GOMEMLIMIT=1073741824\"
EOF'"

ssh $SERVER "sudo mkdir -p /etc/systemd/system/sslcat.service.d && \
    sudo mv /tmp/sslcat-env.conf /etc/systemd/system/sslcat.service.d/env.conf && \
    sudo systemctl daemon-reload"

echo "已设置环境变量："
echo "  GOGC=100 (减少 GC 频率)"
echo "  GOMEMLIMIT=1073741824 (1GB 内存限制)"
echo ""

# 3. 重启服务
echo "[3/4] 重启 sslcat 服务..."
ssh $SERVER "sudo systemctl restart sslcat"
sleep 5

# 4. 验证
echo "[4/4] 验证服务状态..."
ssh $SERVER "sudo systemctl status sslcat --no-pager | head -20"
echo ""

echo "=== 快速修复完成！==="
echo ""
echo "等待 30 秒后检查 CPU 使用情况..."
sleep 30

echo ""
echo "当前 CPU 使用情况："
ssh $SERVER "ps aux | grep -E 'PID|sslcat' | grep -v grep"
echo ""

echo "注意：这是临时修复方案，通过环境变量优化 GC。"
echo "完整修复需要重新编译包含代码优化的版本。"
echo ""
echo "要应用完整修复（包括 HTTP Transport 优化），请："
echo "1. 启动 Docker Desktop"
echo "2. 运行: make docker-cgo-extract"
echo "3. 运行完整部署脚本"

