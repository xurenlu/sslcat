#!/bin/bash

echo "=== SSLCat 用户管理问题诊断脚本 ==="

# 检查数据库
echo "1. 检查用户数据库..."
sqlite3 data/users.db "SELECT username, role, is_active FROM users;" 2>/dev/null || echo "无法访问数据库文件"

# 检查服务器进程
echo -e "\n2. 检查服务器状态..."
if pgrep -f "sslcat" > /dev/null; then
    echo "✓ SSLCat 服务器正在运行"
else
    echo "✗ SSLCat 服务器未运行"
fi

# 检查端口
echo -e "\n3. 检查端口状态..."
if lsof -i :9933 > /dev/null 2>&1; then
    echo "✓ 端口 9933 正在监听"
else
    echo "✗ 端口 9933 未监听"
fi

# 检查配置文件
echo -e "\n4. 检查配置文件..."
if [ -f "data/sslcat.conf" ]; then
    echo "✓ 配置文件存在"
    ADMIN_PREFIX=$(grep -o '"admin_prefix":"[^"]*"' data/sslcat.conf | cut -d'"' -f4)
    echo "管理面板前缀: $ADMIN_PREFIX"
else
    echo "✗ 配置文件不存在"
fi

# 检查前端资源
echo -e "\n5. 检查前端资源..."
if [ -f "internal/assets/frontend/index.html" ]; then
    echo "✓ 前端资源已部署"
    echo "前端文件数量: $(find internal/assets/frontend -type f | wc -l)"
else
    echo "✗ 前端资源未部署"
fi

echo -e "\n=== 诊断建议 ==="
echo "如果用户管理页面仍然显示'获取用户列表失败'，请："
echo "1. 打开浏览器开发者工具查看控制台日志"
echo "2. 检查网络面板中的API请求状态"
echo "3. 确保已正确登录并具有管理员权限"
echo "4. 重启SSLCat服务器："
echo "   sudo pkill -f sslcat"
echo "   sudo go run ./main.go --port=9933 --config=./sslcat.conf --log-level=debug"

echo -e "\n=== 快速测试命令 ==="
echo "测试API端点（需要先登录）："
echo "curl -c cookies.txt -b cookies.txt 'http://localhost:9933${ADMIN_PREFIX:-/sslcat-panel}/api/users'"
