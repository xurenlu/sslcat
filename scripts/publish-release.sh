#!/usr/bin/env bash

# SSLCat 发布脚本
# 将已编译的文件发布到 GitHub Release

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}║              SSLCat GitHub Release 发布工具                ║${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 配置
DIST_DIR="${1:-dist}"

# 检查 dist 目录
if [ ! -d "$DIST_DIR" ]; then
    echo -e "${RED}❌ 目录不存在: ${DIST_DIR}${NC}"
    echo -e "${YELLOW}💡 请先编译或指定正确的目录${NC}"
    echo -e "${YELLOW}   用法: $0 [dist目录]${NC}"
    exit 1
fi

# 检查是否有文件
FILE_COUNT=$(find "$DIST_DIR" -type f \( -name "*.tar.gz" -o -name "*.zip" \) | wc -l | tr -d ' ')
if [ "$FILE_COUNT" -eq 0 ]; then
    echo -e "${RED}❌ 在 ${DIST_DIR} 中没有找到任何 .tar.gz 或 .zip 文件${NC}"
    exit 1
fi

echo -e "${GREEN}✓ 找到 ${FILE_COUNT} 个发布文件${NC}"
echo ""

# 检查 GitHub CLI
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ GitHub CLI (gh) 未安装${NC}"
    echo -e "${YELLOW}💡 请运行: brew install gh${NC}"
    exit 1
fi

# 检查是否已登录
if ! gh auth status &> /dev/null; then
    echo -e "${RED}❌ 未登录 GitHub CLI${NC}"
    echo -e "${YELLOW}💡 请运行: gh auth login${NC}"
    exit 1
fi

echo -e "${GREEN}✓ GitHub CLI 已就绪${NC}"
echo ""

# 显示文件列表
echo -e "${BLUE}📦 待发布的文件:${NC}"
ls -lh "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.zip 2>/dev/null || true
echo ""

# 获取当前版本
CURRENT_VERSION=$(git describe --tags --always 2>/dev/null || echo "")
if [ -z "$CURRENT_VERSION" ]; then
    CURRENT_VERSION=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
fi

echo -e "${MAGENTA}📋 版本信息${NC}"
echo -e "   当前版本: ${GREEN}${CURRENT_VERSION}${NC}"
echo ""

# 询问版本号
echo -e -n "${YELLOW}请输入要发布的版本号 [${CURRENT_VERSION}]: ${NC}"
read VERSION
if [ -z "$VERSION" ]; then
    VERSION="$CURRENT_VERSION"
fi

echo -e "${GREEN}✓ 将发布版本: ${VERSION}${NC}"
echo ""

# 检查标签是否存在
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ 标签 ${VERSION} 已存在${NC}"
else
    echo -e "${YELLOW}⚠️  标签 ${VERSION} 不存在${NC}"
    echo -e -n "${YELLOW}是否创建新标签？ [y/N]: ${NC}"
    read CREATE_TAG
    if [[ "$CREATE_TAG" =~ ^[Yy]$ ]]; then
        git tag "$VERSION"
        echo -e "${GREEN}✓ 已创建标签: ${VERSION}${NC}"
        
        echo -e -n "${YELLOW}是否推送标签到远程？ [y/N]: ${NC}"
        read PUSH_TAG
        if [[ "$PUSH_TAG" =~ ^[Yy]$ ]]; then
            git push origin "$VERSION"
            echo -e "${GREEN}✓ 标签已推送${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  继续使用版本号 ${VERSION}（无标签）${NC}"
    fi
fi

echo ""

# 检查 Release 是否已存在
if gh release view "$VERSION" &> /dev/null; then
    echo -e "${YELLOW}⚠️  Release ${VERSION} 已存在${NC}"
    echo -e -n "${YELLOW}是否删除现有 Release 并重新创建？ [y/N]: ${NC}"
    read DELETE_RELEASE
    if [[ "$DELETE_RELEASE" =~ ^[Yy]$ ]]; then
        gh release delete "$VERSION" --yes
        echo -e "${GREEN}✓ 已删除现有 Release${NC}"
    else
        echo -e "${RED}❌ 取消发布${NC}"
        exit 1
    fi
fi

echo ""

# 生成 Release 说明
echo -e "${BLUE}📝 生成 Release 说明...${NC}"
echo ""

# 尝试从 CHANGELOG.md 提取当前版本的说明
CHANGELOG_NOTES=""
if [ -f "CHANGELOG.md" ]; then
    # 提取当前版本的 CHANGELOG 内容
    CHANGELOG_NOTES=$(awk "/## \[${VERSION#v}\]|## ${VERSION}/{flag=1; next} /^## /{flag=0} flag" CHANGELOG.md | head -50)
fi

# 如果没有找到 CHANGELOG，使用默认模板
if [ -z "$CHANGELOG_NOTES" ]; then
    RELEASE_NOTES="## SSLCat ${VERSION}

### 📦 下载

选择适合你系统的版本下载：

- **Linux AMD64**: 完全静态链接，支持所有 Linux 发行版
- **Linux ARM64**: 完全静态链接，支持 ARM64 服务器
- **macOS Intel**: 支持 Intel Mac
- **macOS Apple Silicon**: 支持 M1/M2/M3 Mac
- **Windows AMD64**: 支持 Windows 10/11 x64
- **Windows ARM64**: 支持 Windows on ARM

### ✨ 特性

- ✅ 完整的 CGO 支持（WebP、SQLite 等）
- ✅ Linux 版本完全静态链接，零依赖
- ✅ 高性能反向代理
- ✅ 自动 SSL 证书管理
- ✅ 图片优化和压缩
- ✅ 智能缓存系统
- ✅ Web 管理界面

### 📚 文档

- [快速开始](https://github.com/xurenlu/sslcat#quick-start)
- [完整文档](https://github.com/xurenlu/sslcat/tree/main/docs)
- [部署指南](https://github.com/xurenlu/sslcat/tree/main/deploy)

### 🔐 校验和

下载后请验证文件完整性：
\`\`\`bash
sha256sum -c sha256sum.txt
\`\`\`

### 📞 支持

- [GitHub Issues](https://github.com/xurenlu/sslcat/issues)
- [GitHub Discussions](https://github.com/xurenlu/sslcat/discussions)
"
else
    # 使用 CHANGELOG 内容
    RELEASE_NOTES="## SSLCat ${VERSION}

${CHANGELOG_NOTES}

---

### 📦 下载

选择适合你系统的版本下载。所有 Linux 版本都是完全静态链接，无需任何依赖。

### 🔐 校验和

下载后请验证文件完整性：
\`\`\`bash
sha256sum -c sha256sum.txt
\`\`\`

### 📚 文档

- [快速开始](https://github.com/xurenlu/sslcat#quick-start)
- [完整文档](https://github.com/xurenlu/sslcat/tree/main/docs)
"
fi

# 显示 Release 说明预览
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "$RELEASE_NOTES"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# 询问是否编辑
echo -e -n "${YELLOW}是否编辑 Release 说明？ [y/N]: ${NC}"
read EDIT_NOTES
if [[ "$EDIT_NOTES" =~ ^[Yy]$ ]]; then
    # 创建临时文件
    TEMP_FILE=$(mktemp)
    echo "$RELEASE_NOTES" > "$TEMP_FILE"
    
    # 使用编辑器
    ${EDITOR:-vim} "$TEMP_FILE"
    
    # 读取编辑后的内容
    RELEASE_NOTES=$(cat "$TEMP_FILE")
    rm "$TEMP_FILE"
    
    echo -e "${GREEN}✓ Release 说明已更新${NC}"
fi

echo ""

# 确认发布
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}准备发布到 GitHub Release${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "   版本: ${GREEN}${VERSION}${NC}"
echo -e "   文件数: ${GREEN}${FILE_COUNT}${NC}"
echo -e "   仓库: ${CYAN}$(gh repo view --json nameWithOwner -q .nameWithOwner)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e -n "${YELLOW}确认发布？ [y/N]: ${NC}"
read CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo -e "${RED}❌ 取消发布${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}🚀 开始发布...${NC}"
echo ""

# 创建 Release
echo -e "${BLUE}📝 创建 GitHub Release...${NC}"

# 保存 Release 说明到临时文件
NOTES_FILE=$(mktemp)
echo "$RELEASE_NOTES" > "$NOTES_FILE"

# 创建 Release 并上传文件
gh release create "$VERSION" \
    --title "SSLCat ${VERSION}" \
    --notes-file "$NOTES_FILE" \
    "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.zip 2>/dev/null || \
gh release create "$VERSION" \
    --title "SSLCat ${VERSION}" \
    --notes-file "$NOTES_FILE" \
    "$DIST_DIR"/*

# 清理临时文件
rm "$NOTES_FILE"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ 发布成功！${NC}"
    echo ""
    
    # 获取 Release URL
    REPO_URL=$(gh repo view --json nameWithOwner -q .nameWithOwner)
    RELEASE_URL="https://github.com/${REPO_URL}/releases/tag/${VERSION}"
    
    echo -e "${CYAN}🔗 Release 地址:${NC}"
    echo -e "   ${RELEASE_URL}"
    echo ""
    
    # 显示下载统计
    echo -e "${BLUE}📊 Release 信息:${NC}"
    gh release view "$VERSION" --json tagName,name,createdAt,assets \
        --jq '.assets[] | "   - \(.name) (\(.size / 1024 / 1024 | floor)MB)"'
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║                    🎉 发布完成！                           ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
else
    echo ""
    echo -e "${RED}❌ 发布失败${NC}"
    echo -e "${YELLOW}💡 请检查错误信息并重试${NC}"
    exit 1
fi

