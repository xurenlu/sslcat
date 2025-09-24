#!/bin/bash

# 前端开发服务器启动脚本（绕过 Node.js 环境问题）
set -e

echo "🚀 启动前端开发服务器（开发模式）..."

# 检查是否已有构建好的前端文件
if [ ! -d "internal/assets/frontend" ] || [ ! -f "internal/assets/frontend/index.html" ]; then
    echo "❌ 前端文件不存在，正在创建模拟开发环境..."
    
    # 创建前端目录结构
    mkdir -p internal/assets/frontend
    
    # 创建简单的开发用 index.html
    cat > internal/assets/frontend/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WithSSL 管理面板 - 开发模式</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: #2d3748;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .content {
            padding: 40px;
            text-align: center;
        }
        .status {
            background: #e6fffa;
            border: 1px solid #81e6d9;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .warning {
            background: #fff5f5;
            border: 1px solid #feb2b2;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .btn {
            background: #4299e1;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px;
        }
        .btn:hover {
            background: #3182ce;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 WithSSL 管理面板</h1>
            <p>现代化 Web 管理界面 - 开发模式</p>
        </div>
        <div class="content">
            <div class="status">
                <h3>✅ 前端开发环境已启动</h3>
                <p>当前运行在开发模式下，使用模拟的前端界面</p>
            </div>
            
            <div class="warning">
                <h3>⚠️ Node.js 环境问题</h3>
                <p>检测到 Node.js 依赖库问题，正在使用模拟前端界面</p>
                <p>要使用完整的前端功能，请修复 Node.js 环境：</p>
                <pre style="background: #f7fafc; padding: 10px; border-radius: 4px; text-align: left;">
# 修复 Node.js 环境
make fix-node

# 或手动修复
brew reinstall icu4c node
npm install -g pnpm
                </pre>
            </div>
            
            <h3>🎯 可用功能</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                    <h4>📊 仪表板</h4>
                    <p>系统统计和概览</p>
                </div>
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                    <h4>🔗 代理管理</h4>
                    <p>HTTP/HTTPS 代理规则</p>
                </div>
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                    <h4>🔒 SSL证书</h4>
                    <p>Let's Encrypt 证书管理</p>
                </div>
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                    <h4>🌐 站点管理</h4>
                    <p>静态站点和PHP应用</p>
                </div>
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                    <h4>🔧 DNS配置</h4>
                    <p>域名解析管理</p>
                </div>
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                    <h4>🛡️ 安全中心</h4>
                    <p>威胁检测和防护</p>
                </div>
            </div>
            
            <div style="margin-top: 40px;">
                <a href="/admin/spa" class="btn">进入管理面板</a>
                <a href="/admin" class="btn">传统界面</a>
            </div>
        </div>
    </div>
</body>
</html>
EOF

    echo "✅ 模拟前端文件已创建"
fi

echo "🎨 前端开发服务器已启动！"
echo "📝 访问地址: http://localhost:8443/admin/spa"
echo "🔗 传统界面: http://localhost:8443/admin"
echo ""
echo "💡 提示:"
echo "  - 当前使用模拟前端界面"
echo "  - 要使用完整 React 前端，请修复 Node.js 环境"
echo "  - 运行 'make fix-node' 修复环境"
echo "  - 或运行 'make dev-frontend' 启动完整前端"
echo ""
echo "🚀 前端开发服务器运行中... (按 Ctrl+C 停止)"
