#!/bin/bash

# SSLcat 快速启动脚本

# 创建必要的目录
mkdir -p data/certs data/keys data/logs

# 复制示例配置文件
if [ ! -f "sslcat.conf" ]; then
    cp sslcat.conf.example sslcat.conf
    echo "已创建配置文件 sslcat.conf"
fi

# 启动程序
echo "启动 SSLcat 服务器..."
echo "管理面板: http://localhost:8080/sslcat-panel"
echo "默认用户名: admin"
echo "默认密码: admin*9527"
echo ""
echo "按 Ctrl+C 停止服务器"
echo ""

./sslcat --config sslcat.conf --port 8080 --log-level debug
