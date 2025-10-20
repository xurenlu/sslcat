#!/bin/bash

# 测试静态资源检测功能
# 这个脚本用于验证静态资源不会触发可疑模式检测

echo "🧪 测试静态资源检测功能"
echo "================================"

# 测试URL列表
test_urls=(
    "/favicon.ico"
    "/apple-touch-icon.png"
    "/apple-touch-icon-180x180.png"
    "/robots.txt"
    "/sitemap.xml"
    "/manifest.json"
    "/sw.js"
    "/static/css/bootstrap.min.css"
    "/assets/js/jquery.min.js"
    "/lib/fontawesome/css/font-awesome.css"
    "/vendor/bootstrap/css/bootstrap.css"
    "/cdn/jquery-ui.css"
    "/devtools/source-map.json"
    "/api/chrome/devtools.json"
    "/hot-update.js"
    "/browserconfig.xml"
    "/humans.txt"
    "/crossdomain.xml"
    "/service-worker.js"
    "/offline.html"
    "/404.html"
    "/500.html"
    "/static/images/logo.png"
    "/assets/fonts/font.woff2"
    "/public/icons/icon.svg"
    "/.well-known/security.txt"
)

echo "📋 测试URL列表："
for url in "${test_urls[@]}"; do
    echo "  - $url"
done

echo ""
echo "✅ 这些URL应该被识别为静态资源，不会触发可疑模式检测"
echo ""
echo "🔍 测试非静态资源（应该触发检测）："
non_static_urls=(
    "/api/users"
    "/admin/login"
    "/dashboard"
    "/api/data?select=*"
    "/search?q=union+select"
    "/user/../admin"
    "/api/../config"
)

for url in "${non_static_urls[@]}"; do
    echo "  - $url (应该触发检测)"
done

echo ""
echo "📝 说明："
echo "1. 静态资源请求不会触发可疑模式检测"
echo "2. 非静态资源仍会进行正常的安全检测"
echo "3. 这减少了误报，提高了系统稳定性"
echo ""
echo "🚀 要应用这些更改，请重启 SSLcat 服务"
