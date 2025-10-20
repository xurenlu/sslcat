#!/bin/bash

# SSLcat 嵌入式部署脚本
# 使用 Go embed 将所有资源嵌入到二进制文件中，无需手工复制文件

set -e

echo "=========================================="
echo "SSLcat 嵌入式部署脚本"
echo "=========================================="

# 检查Go版本
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.16"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ 需要Go $REQUIRED_VERSION或更高版本，当前版本: $GO_VERSION"
    exit 1
fi

echo "✅ Go版本检查通过: $GO_VERSION"

# 1. 编译阶段
echo ""
echo "🔨 第一步：编译应用程序"
echo "========================"

# 检查是否是交叉编译
if [ "$1" = "linux" ]; then
    echo "🐧 交叉编译Linux 64位版本..."
    GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o withssl-linux .
    BINARY_NAME="withssl-linux"
    echo "✅ 交叉编译完成: $BINARY_NAME"
else
    echo "🏗️ 编译本地版本..."
    go build -ldflags "-s -w" -o withssl .
    BINARY_NAME="withssl"
    echo "✅ 编译完成: $BINARY_NAME"
fi

# 检查二进制文件大小
BINARY_SIZE=$(du -h "$BINARY_NAME" | awk '{print $1}')
echo "📦 二进制文件大小: $BINARY_SIZE"

# 2. 验证嵌入的资源
echo ""
echo "🔍 第二步：验证嵌入资源"
echo "======================"

echo "📁 检查嵌入的HTML模板文件："
find internal/assets/templates -name "*.html" 2>/dev/null | while read file; do
    echo "   ✅ $(basename "$file")"
done

echo "🌍 检查嵌入的翻译文件："
find internal/assets/i18n -name "*.json" 2>/dev/null | while read file; do
    lang=$(basename "$file" .json)
    echo "   ✅ $lang"
done

# 3. 创建部署包
echo ""
echo "📦 第三步：创建部署包"
echo "==================="

DEPLOY_DIR="deploy"
rm -rf "$DEPLOY_DIR"
mkdir -p "$DEPLOY_DIR"

# 复制二进制文件
cp "$BINARY_NAME" "$DEPLOY_DIR/"

# 复制配置文件
cp sslcat.conf.example "$DEPLOY_DIR/sslcat.conf"
cp withssl-advanced.conf.example "$DEPLOY_DIR/" 2>/dev/null || true

# 复制脚本
cp install.sh "$DEPLOY_DIR/" 2>/dev/null || true
cp start.sh "$DEPLOY_DIR/" 2>/dev/null || true

# 创建部署说明
cat > "$DEPLOY_DIR/README.md" << 'EOF'
# SSLcat 部署包

此部署包包含了使用 Go embed 特性的 SSLcat 二进制文件，所有 HTML 模板和翻译文件都已嵌入到二进制文件中。

## 部署优势

✅ **单文件部署**: 只需要一个二进制文件，无需手工复制模板和翻译文件
✅ **零依赖**: 所有资源都嵌入在二进制文件中
✅ **简化运维**: 不用担心文件丢失或路径问题
✅ **版本一致**: 确保模板和代码版本完全一致

## 快速部署

1. 上传二进制文件到服务器
2. 复制并修改配置文件
3. 运行服务

```bash
# 1. 复制配置文件
cp sslcat.conf.example sslcat.conf

# 2. 编辑配置
nano sslcat.conf

# 3. 启动服务
./withssl --config sslcat.conf
```

## 文件说明

- `withssl` / `withssl-linux`: 主程序二进制文件（包含所有嵌入资源）
- `sslcat.conf`: 配置文件示例
- `withssl-advanced.conf.example`: 高级配置示例
- `install.sh`: 系统安装脚本（可选）
- `start.sh`: 快速启动脚本（可选）

## 嵌入的资源

### HTML 模板
- base.html - 基础模板
- login.html - 登录页面
- dashboard.html - 仪表板
- mobile.html - 移动端界面
- charts.html - 图表分析页面
- default.html - 默认页面

### 多语言翻译
- zh-CN.json - 简体中文
- en-US.json - 英语
- ja-JP.json - 日语
- es-ES.json - 西班牙语
- fr-FR.json - 法语
- ru-RU.json - 俄语

## 技术说明

本版本使用了 Go 1.16+ 的 embed 特性，将所有静态资源嵌入到二进制文件中：

```go
//go:embed templates/*.html
var TemplatesFS embed.FS

//go:embed i18n/*.json
var I18nFS embed.FS
```

这确保了：
- 部署简单（单文件）
- 资源版本一致
- 运行时性能优异
- 无外部文件依赖
EOF

echo "✅ 部署包创建完成: $DEPLOY_DIR/"

# 4. 生成部署命令
echo ""
echo "🚀 第四步：生成部署命令"
echo "======================"

echo "📋 服务器部署命令："
echo ""
echo "# 1. 上传文件到服务器"
echo "scp -r $DEPLOY_DIR/ user@server:/opt/sslcat/"
echo ""
echo "# 2. 在服务器上执行"
echo "cd /opt/sslcat/"
echo "chmod +x $BINARY_NAME"
echo "cp sslcat.conf.example sslcat.conf"
echo "# 编辑配置文件..."
echo "nano sslcat.conf"
echo "# 启动服务"
echo "./$BINARY_NAME --config sslcat.conf"

# 5. 清理
echo ""
echo "🧹 第五步：清理临时文件"
echo "======================"

if [ "$BINARY_NAME" != "withssl" ]; then
    rm -f "$BINARY_NAME"
    echo "✅ 清理临时文件: $BINARY_NAME"
fi

echo ""
echo "🎉 嵌入式部署包制作完成！"
echo ""
echo "📊 部署包内容："
ls -la "$DEPLOY_DIR/"

echo ""
echo "💡 使用建议："
echo "1. 所有资源已嵌入，只需上传 $DEPLOY_DIR/ 目录"
echo "2. 无需手工复制 HTML 或翻译文件"
echo "3. 确保配置文件符合你的环境"
echo "4. 建议使用 systemd 管理服务"

echo ""
echo "=========================================="
