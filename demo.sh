#!/bin/bash

# WithSSL 演示脚本

echo "==============================================="
echo "WithSSL SSL 代理服务器 - 演示脚本"
echo "==============================================="
echo ""

# 检查是否存在二进制文件
if [ ! -f "withssl" ]; then
    echo "🔨 构建 WithSSL..."
    go build -o withssl main.go
    if [ $? -ne 0 ]; then
        echo "❌ 构建失败，请检查 Go 环境"
        exit 1
    fi
    echo "✅ 构建完成"
fi

# 创建必要目录
echo "📁 创建数据目录..."
mkdir -p data/certs data/keys data/logs

# 创建配置文件
if [ ! -f "withssl.conf" ]; then
    echo "⚙️  创建配置文件..."
    cp withssl.conf.example withssl.conf
fi

echo ""
echo "🚀 启动 WithSSL 服务器..."
echo ""
echo "📋 服务信息："
echo "   • 监听端口：8080"
echo "   • 管理面板：http://localhost:8080/withssl-panel/"
echo "   • 默认用户名：admin"
echo "   • 默认密码：admin*9527"
echo ""
echo "🛡️  安全功能："
echo "   • IP 封禁：1分钟3次错误尝试"
echo "   • User-Agent 过滤：只允许常见浏览器"
echo "   • 访问日志：记录所有访问"
echo ""
echo "🔧 测试命令："
echo "   # 访问登录页面"
echo "   curl -H \"User-Agent: Mozilla/5.0\" http://localhost:8080/withssl-panel/login"
echo ""
echo "   # 测试未配置域名"
echo "   curl -H \"User-Agent: Mozilla/5.0\" -H \"Host: test.example.com\" http://localhost:8080/"
echo ""
echo "   # 查看进程"
echo "   ps aux | grep withssl"
echo ""
echo "按 Ctrl+C 停止服务器"
echo "==============================================="
echo ""

# 启动服务器
exec ./withssl --config withssl.conf --port 8080 --log-level info
