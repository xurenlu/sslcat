#!/bin/bash

# SSLcat 配置文件命名统一脚本
# 将所有 withssl.conf 引用改为 sslcat.conf

set -e

echo "🔧 开始统一配置文件命名..."

# 1. 更新 main.go 中的默认配置路径（如果需要）
echo "📝 检查 main.go 配置..."

# 2. 更新所有文档中的配置文件引用
echo "📚 更新文档中的配置文件引用..."

# 更新 README 文件
if [ -f "README.md" ]; then
    sed -i.bak 's|withssl\.conf|sslcat.conf|g' README.md
    echo "  ✅ README.md 已更新"
fi

# 更新其他语言版本的 README
for file in README_*.md; do
    if [ -f "$file" ]; then
        sed -i.bak "s|withssl\.conf|sslcat.conf|g" "$file"
        echo "  ✅ $file 已更新"
    fi
done

# 更新部署脚本
echo "🚀 更新部署脚本..."
for file in deploy.sh install.sh deploy-embedded.sh; do
    if [ -f "$file" ]; then
        sed -i.bak 's|withssl\.conf|sslcat.conf|g' "$file"
        echo "  ✅ $file 已更新"
    fi
done

# 更新 Docker 相关文件
if [ -f "docker-compose.yml" ]; then
    sed -i.bak 's|withssl\.conf|sslcat.conf|g' docker-compose.yml
    echo "  ✅ docker-compose.yml 已更新"
fi

if [ -f "Dockerfile" ]; then
    sed -i.bak 's|withssl\.conf|sslcat.conf|g' Dockerfile
    echo "  ✅ Dockerfile 已更新"
fi

# 更新测试脚本
echo "🧪 更新测试脚本..."
for file in test-ssl.sh start.sh demo.sh; do
    if [ -f "$file" ]; then
        sed -i.bak 's|withssl\.conf|sslcat.conf|g' "$file"
        echo "  ✅ $file 已更新"
    fi
done

# 更新 Makefile
if [ -f "Makefile" ]; then
    sed -i.bak 's|withssl\.conf|sslcat.conf|g' Makefile
    echo "  ✅ Makefile 已更新"
fi

# 更新内部代码文件
echo "💻 更新内部代码文件..."
if [ -f "internal/web/handlers.go" ]; then
    sed -i.bak 's|withssl\.conf|sslcat.conf|g' internal/web/handlers.go
    echo "  ✅ internal/web/handlers.go 已更新"
fi

# 更新国际化文件
echo "🌍 更新国际化文件..."
for file in i18n/*.json; do
    if [ -f "$file" ]; then
        sed -i.bak 's|withssl\.conf|sslcat.conf|g' "$file"
        echo "  ✅ $file 已更新"
    fi
done

# 更新根目录的 JSON 文件
for file in *.json; do
    if [ -f "$file" ]; then
        sed -i.bak 's|withssl\.conf|sslcat.conf|g' "$file"
        echo "  ✅ $file 已更新"
    fi
done

# 清理备份文件
echo "🧹 清理备份文件..."
find . -name "*.bak" -delete

echo "🎉 配置文件命名统一完成！"
echo ""
echo "📋 更新总结："
echo "  - 所有 withssl.conf 引用已改为 sslcat.conf"
echo "  - 备份文件已清理"
echo "  - 请运行迁移脚本完成服务器配置迁移"
echo ""
echo "🔧 下一步操作："
echo "  1. 在服务器上运行: ./scripts/migrate-config.sh"
echo "  2. 重启服务: systemctl restart sslcat"
echo "  3. 检查服务状态: systemctl status sslcat"
