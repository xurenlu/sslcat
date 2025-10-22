#!/bin/bash

# 前端资源预压缩脚本
# 在构建前端后运行，为静态资源生成预压缩版本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  SSLCat 静态资源预压缩工具${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# 检查参数
ASSETS_DIR="${1:-$PROJECT_ROOT/internal/assets/frontend/assets}"

if [ ! -d "$ASSETS_DIR" ]; then
    echo -e "${RED}错误：资源目录不存在: $ASSETS_DIR${NC}"
    echo "用法: $0 [资源目录路径]"
    echo "示例: $0 ./internal/assets/frontend/assets"
    exit 1
fi

echo -e "${BLUE}资源目录：${NC}$ASSETS_DIR"
echo ""

# 检查依赖
HAVE_GZIP=true
HAVE_BROTLI=true

if ! command -v gzip &> /dev/null; then
    echo -e "${YELLOW}警告：未找到 gzip 命令${NC}"
    HAVE_GZIP=false
fi

if ! command -v brotli &> /dev/null; then
    echo -e "${YELLOW}警告：未找到 brotli 命令${NC}"
    echo -e "${YELLOW}提示：可以通过以下方式安装：${NC}"
    echo "  macOS:   brew install brotli"
    echo "  Ubuntu:  sudo apt-get install brotli"
    echo "  CentOS:  sudo yum install brotli"
    HAVE_BROTLI=false
fi

if [ "$HAVE_GZIP" = false ] && [ "$HAVE_BROTLI" = false ]; then
    echo -e "${RED}错误：gzip 和 brotli 都不可用${NC}"
    exit 1
fi

echo ""

# 统计变量
total_files=0
gzip_count=0
brotli_count=0
gzip_total_original=0
gzip_total_compressed=0
brotli_total_original=0
brotli_total_compressed=0

# 可压缩的文件扩展名
COMPRESSIBLE_EXTS=("js" "css" "html" "htm" "json" "xml" "svg" "txt" "md")

echo -e "${BLUE}开始压缩文件...${NC}"
echo ""

# 递归处理文件
process_file() {
    local file="$1"
    local filename=$(basename "$file")
    local ext="${filename##*.}"
    
    # 检查是否是可压缩类型
    local should_compress=false
    for comp_ext in "${COMPRESSIBLE_EXTS[@]}"; do
        if [ "$ext" = "$comp_ext" ]; then
            should_compress=true
            break
        fi
    done
    
    if [ "$should_compress" = false ]; then
        return
    fi
    
    # 检查文件大小（小于1KB不压缩）
    local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
    if [ "$file_size" -lt 1024 ]; then
        return
    fi
    
    ((total_files++))
    
    local relative_path="${file#$ASSETS_DIR/}"
    echo -e "${YELLOW}压缩:${NC} $relative_path ($(numfmt --to=iec-i --suffix=B $file_size 2>/dev/null || echo "${file_size} bytes"))"
    
    # Gzip 压缩 (级别 9 - 最高压缩率)
    if [ "$HAVE_GZIP" = true ]; then
        gzip -9 -k -f "$file" 2>/dev/null
        if [ -f "${file}.gz" ]; then
            local gz_size=$(stat -f%z "${file}.gz" 2>/dev/null || stat -c%s "${file}.gz" 2>/dev/null)
            local reduction=$(( 100 - (gz_size * 100 / file_size) ))
            echo -e "  ${GREEN}✓ Gzip:${NC}   $(numfmt --to=iec-i --suffix=B $gz_size 2>/dev/null || echo "${gz_size} bytes") (${reduction}% 减小)"
            ((gzip_count++))
            gzip_total_original=$((gzip_total_original + file_size))
            gzip_total_compressed=$((gzip_total_compressed + gz_size))
        fi
    fi
    
    # Brotli 压缩 (级别 11 - 最高压缩率)
    if [ "$HAVE_BROTLI" = true ]; then
        brotli -q 11 -f -k "$file" 2>/dev/null
        if [ -f "${file}.br" ]; then
            local br_size=$(stat -f%z "${file}.br" 2>/dev/null || stat -c%s "${file}.br" 2>/dev/null)
            local reduction=$(( 100 - (br_size * 100 / file_size) ))
            echo -e "  ${GREEN}✓ Brotli:${NC} $(numfmt --to=iec-i --suffix=B $br_size 2>/dev/null || echo "${br_size} bytes") (${reduction}% 减小)"
            ((brotli_count++))
            brotli_total_original=$((brotli_total_original + file_size))
            brotli_total_compressed=$((brotli_total_compressed + br_size))
        fi
    fi
    
    echo ""
}

# 导出函数供 find 使用
export -f process_file
export ASSETS_DIR
export HAVE_GZIP
export HAVE_BROTLI
export total_files
export gzip_count
export brotli_count
export gzip_total_original
export gzip_total_compressed
export brotli_total_original
export brotli_total_compressed
export -f $(declare -F | awk '{print $3}')

# 查找并处理所有文件
find "$ASSETS_DIR" -type f \( \
    -name "*.js" -o \
    -name "*.css" -o \
    -name "*.html" -o \
    -name "*.htm" -o \
    -name "*.json" -o \
    -name "*.xml" -o \
    -name "*.svg" -o \
    -name "*.txt" -o \
    -name "*.md" \
\) ! -name "*.gz" ! -name "*.br" | while read -r file; do
    process_file "$file"
done

# 计算总的压缩统计
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  压缩完成！${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${BLUE}统计信息：${NC}"
echo "  处理文件总数: $total_files"
echo ""

if [ "$HAVE_GZIP" = true ] && [ $gzip_count -gt 0 ]; then
    gzip_reduction=$(( 100 - (gzip_total_compressed * 100 / gzip_total_original) ))
    echo -e "${GREEN}Gzip 压缩：${NC}"
    echo "  压缩文件数: $gzip_count"
    echo "  原始大小: $(numfmt --to=iec-i --suffix=B $gzip_total_original 2>/dev/null || echo "$gzip_total_original bytes")"
    echo "  压缩后: $(numfmt --to=iec-i --suffix=B $gzip_total_compressed 2>/dev/null || echo "$gzip_total_compressed bytes")"
    echo "  总体减小: ${gzip_reduction}%"
    echo ""
fi

if [ "$HAVE_BROTLI" = true ] && [ $brotli_count -gt 0 ]; then
    brotli_reduction=$(( 100 - (brotli_total_compressed * 100 / brotli_total_original) ))
    echo -e "${GREEN}Brotli 压缩：${NC}"
    echo "  压缩文件数: $brotli_count"
    echo "  原始大小: $(numfmt --to=iec-i --suffix=B $brotli_total_original 2>/dev/null || echo "$brotli_total_original bytes")"
    echo "  压缩后: $(numfmt --to=iec-i --suffix=B $brotli_total_compressed 2>/dev/null || echo "$brotli_total_compressed bytes")"
    echo "  总体减小: ${brotli_reduction}%"
    echo ""
fi

# 查找最大的压缩文件
echo -e "${BLUE}最大的压缩文件（前5个）：${NC}"
find "$ASSETS_DIR" -type f \( -name "*.js" -o -name "*.css" \) -exec du -h {} + | sort -hr | head -5 | while read -r size file; do
    filename=$(basename "$file")
    if [ -f "${file}.gz" ]; then
        gz_size=$(du -h "${file}.gz" | cut -f1)
        echo "  $filename: $size → ${gz_size} (gzip)"
    fi
done

echo ""
echo -e "${YELLOW}提示：${NC}"
echo "  1. 预压缩文件会在程序启动时自动使用"
echo "  2. 支持的浏览器会自动收到压缩版本"
echo "  3. 重新构建前端时需要重新运行此脚本"
echo ""
echo -e "${GREEN}完成！✨${NC}"

