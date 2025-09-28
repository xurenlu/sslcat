#!/bin/bash

# SSLcat 企业级功能演示脚本

echo "🚀 SSLcat 企业级功能演示"
echo "=============================="

# 检查SSLcat是否已编译
if [ ! -f "./sslcat" ]; then
    echo "📦 编译SSLcat..."
    go build -o sslcat main.go
    if [ $? -ne 0 ]; then
        echo "❌ 编译失败"
        exit 1
    fi
    echo "✅ 编译完成"
fi

# 复制企业级配置
echo ""
echo "📋 配置企业级功能..."
cp sslcat-enterprise.conf.example sslcat-demo.conf

# 修改配置以适合演示
cat > sslcat-demo.conf << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": true,
    "access_log_enabled": true,
    "access_log_format": "json",
    "access_log_path": "./data/access.log"
  },
  "ssl": {
    "email": "demo@example.com",
    "staging": true,
    "auto_renew": true,
    "cert_dir": "./data/certs",
    "key_dir": "./data/keys"
  },
  "admin": {
    "username": "admin",
    "password_file": "./data/admin.pass",
    "first_run": true
  },
  "compression": {
    "enabled": true,
    "algorithms": ["br", "gzip"],
    "min_size": 100,
    "level": {
      "gzip": 6,
      "brotli": 6
    }
  },
  "proxy": {
    "rules": [
      {
        "domain": "demo.local",
        "enabled": true,
        "ssl_only": false,
        
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "round_robin",
        "load_balancer_backends": [
          {
            "id": "demo-backend-1",
            "host": "httpbin.org",
            "port": 80,
            "weight": 1,
            "enabled": true,
            "health_check_enabled": true,
            "health_check_path": "/status/200",
            "health_check_method": "GET",
            "expected_status_code": 200
          },
          {
            "id": "demo-backend-2",
            "host": "httpbin.org",
            "port": 80,
            "weight": 1,
            "enabled": true,
            "health_check_enabled": true,
            "health_check_path": "/status/200",
            "health_check_method": "GET",
            "expected_status_code": 200
          }
        ],
        
        "health_check_enabled": true,
        "health_check_interval": 10,
        "health_check_timeout": 5
      }
    ]
  },
  "security": {
    "max_attempts": 10,
    "block_duration": "1m",
    "enable_ua_filter": false,
    "enable_ddos": false
  },
  "cdn_cache": {
    "enabled": true,
    "cache_dir": "./data/cache",
    "max_size_bytes": 104857600,
    "default_ttl_seconds": 300
  },
  "admin_prefix": "/sslcat-panel",
  "cluster": {
    "mode": "standalone"
  },
  "static_sites": [],
  "php_sites": [],
  "runners": {
    "git": {
      "enabled": false
    }
  },
  "threat_intel": {
    "enabled": false
  },
  "notification": {
    "enabled": false
  }
}
EOF

echo "✅ 配置文件已生成: sslcat-demo.conf"

# 创建必要的目录
mkdir -p data/{certs,keys,cache,upstream-cache}

echo ""
echo "🎯 演示功能列表:"
echo "1. 🔄 负载均衡 - Round Robin算法，2个后端"
echo "2. 🏥 健康检查 - 每10秒检查一次后端状态"
echo "3. 📦 Brotli压缩 - 自动压缩文本内容"
echo "4. 💾 上游缓存 - 缓存静态资源"
echo "5. 🔥 配置热重载 - 修改配置自动生效"
echo "6. 🎨 Web管理界面 - 现代化管理面板"

echo ""
echo "🚀 启动SSLcat演示服务器..."
echo "   配置文件: sslcat-demo.conf"
echo "   监听端口: 8080"
echo "   管理面板: http://localhost:8080/sslcat-panel/"
echo "   演示域名: demo.local (需要在hosts文件中添加)"
echo ""

# 启动服务器
echo "💡 提示:"
echo "   1. 访问 http://localhost:8080/sslcat-panel/ 进入管理面板"
echo "   2. 默认账号: admin / admin*9527"
echo "   3. 在hosts文件中添加: 127.0.0.1 demo.local"
echo "   4. 访问 http://demo.local:8080/ 测试负载均衡"
echo "   5. 按 Ctrl+C 停止服务器"
echo ""

# 启动服务器（前台运行以便查看日志）
./sslcat --config sslcat-demo.conf --port 8080

echo ""
echo "🎊 演示结束，感谢使用SSLcat企业级功能！"
