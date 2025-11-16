#!/bin/bash

# 测试剩余256个模板脚本
# 在 47.82.4.54 服务器上运行
# 服务器限制：只能同时运行4个docker，因此并发数设为2

set +e  # 允许单个模板失败时继续测试其他模板

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
SERVER="root@47.82.4.54"
SSLCAT_DIR="/opt/sslcat"
TEST_DIR="/opt/sslcat-test"
BATCH_NUM="${1:-all}"  # all, 1, 2, 3, 4, 5, 6

echo -e "${GREEN}🧪 开始测试剩余模板 (批次: $BATCH_NUM)${NC}"
echo -e "${BLUE}服务器: $SERVER${NC}"
echo -e "${BLUE}项目目录: $SSLCAT_DIR${NC}"
echo ""

# 检查批次文件是否存在
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$BATCH_NUM" != "all" ]; then
    BATCH_FILE="$PROJECT_DIR/scripts/batch-${BATCH_NUM}-templates.txt"
    if [ ! -f "$BATCH_FILE" ]; then
        echo -e "${RED}❌ 错误：找不到批次文件 $BATCH_FILE${NC}"
        exit 1
    fi
    echo -e "${GREEN}📋 批次文件: $BATCH_FILE${NC}"
    TEMPLATE_COUNT=$(wc -l < "$BATCH_FILE")
    echo -e "${GREEN}📊 本批次模板数: $TEMPLATE_COUNT${NC}"
fi

# 读取 GitHub Token（如果存在）
TOKEN_FILE="$PROJECT_DIR/_mine/github-token.txt"
GITHUB_TOKEN=""
if [ -f "$TOKEN_FILE" ]; then
    GITHUB_TOKEN=$(grep -v '^#' "$TOKEN_FILE" | grep 'GITHUB_TOKEN=' | tail -1 | cut -d'=' -f2 | tr -d ' ' | tr -d '"' | tr -d "'")
    if [ -n "$GITHUB_TOKEN" ]; then
        echo -e "${GREEN}✅ 已读取 GitHub Token${NC}"
    fi
fi

# 同步代码到服务器
echo -e "${YELLOW}📥 同步代码到服务器...${NC}"
rsync -avz --exclude 'node_modules' --exclude '.git' --exclude 'dist' --exclude 'build' \
    "$PROJECT_DIR/" "$SERVER:$SSLCAT_DIR/" 2>&1 | tail -5 || {
    echo -e "${YELLOW}⚠️  rsync 警告（继续执行）${NC}"
}

# 确保批次文件被同步
if [ "$BATCH_NUM" != "all" ]; then
    echo -e "${YELLOW}📋 确保批次文件已同步...${NC}"
    scp "$BATCH_FILE" "$SERVER:$SSLCAT_DIR/scripts/batch-${BATCH_NUM}-templates.txt" 2>&1 | tail -2 || {
        echo -e "${RED}❌ 批次文件同步失败${NC}"
        exit 1
    }
else
    echo -e "${YELLOW}📋 同步所有批次文件...${NC}"
    for batch in 1 2 3 4 5 6; do
        BATCH_FILE_LOCAL="$PROJECT_DIR/scripts/batch-${batch}-templates.txt"
        if [ -f "$BATCH_FILE_LOCAL" ]; then
            scp "$BATCH_FILE_LOCAL" "$SERVER:$SSLCAT_DIR/scripts/batch-${batch}-templates.txt" 2>&1 | tail -1 || true
        fi
    done
fi

# 在服务器上执行测试
echo -e "${YELLOW}🚀 连接到服务器并开始测试...${NC}"

ssh $SERVER bash << ENDSSH
set +e

# 设置环境变量
export PATH=\$PATH:/usr/local/go/bin
export GOPATH=/opt/go
export GOBIN=\$GOPATH/bin

# 设置 GitHub Token（如果提供）
if [ -n "$GITHUB_TOKEN" ]; then
    export GITHUB_TOKEN="$GITHUB_TOKEN"
    export GITHUB_PAT="$GITHUB_TOKEN"
    echo "✅ 已设置 GitHub Token"
    
    # 登录到 GitHub Container Registry
    echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$GITHUB_TOKEN" --password-stdin 2>/dev/null && echo "✅ GHCR 登录成功" || echo "⚠️  GHCR 登录失败（可能不需要）"
fi

cd $SSLCAT_DIR

echo "🔧 检查环境..."
# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker 未安装"
    exit 1
fi

# 检查 docker-compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ docker-compose 未安装"
    exit 1
fi

# 检查 Go
if ! command -v go &> /dev/null; then
    echo "❌ Go 未安装"
    exit 1
fi

# 检查磁盘空间
DISK_SPACE=\$(df -h / | tail -1 | awk '{print \$4}')
echo "💾 磁盘空间: \$DISK_SPACE"

# 编译测试工具
echo "📦 编译测试工具..."
cd tools/test-templates
go mod tidy 2>&1 | tail -5
go build -o test-templates . 2>&1 | tail -5

if [ ! -f "./test-templates" ]; then
    echo "❌ 编译失败"
    exit 1
fi

echo "✅ 测试工具编译成功"
chmod +x ./test-templates

# 创建输出目录
mkdir -p $TEST_DIR/results

    # 根据批次执行测试
if [ "$BATCH_NUM" = "all" ]; then
    echo "🧪 测试所有批次..."
    for batch in 1 2 3 4 5 6; do
        BATCH_FILE="$SSLCAT_DIR/scripts/batch-\${batch}-templates.txt"
        if [ ! -f "\$BATCH_FILE" ]; then
            echo "⚠️  批次 \$batch 文件不存在，跳过"
            continue
        fi
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📦 开始测试批次 \$batch"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        BASE_PORT=\$((20000 + (\$batch - 1) * 100))
        OUTPUT_DIR="$TEST_DIR/results/batch-\${batch}"
        mkdir -p "\$OUTPUT_DIR"
        
        TEMPLATE_COUNT=\$(wc -l < "\$BATCH_FILE")
        CURRENT=0
        PASSED=0
        FAILED=0
        SKIPPED=0
        
        # 初始化结果文件
        echo "[]" > "\$OUTPUT_DIR/test-results.json"
        
        while IFS= read -r template; do
            [ -z "\$template" ] && continue
            CURRENT=\$((CURRENT + 1))
            
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "🧪 测试模板 [\$CURRENT/\$TEMPLATE_COUNT]: \$template"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            
            LOG_FILE="$TEST_DIR/results/batch-\${batch}-\${template}.log"
            
            ./test-templates \
                --template "\$template" \
                --templates-dir ../../internal/runner/templates/builtin \
                --parallel 1 \
                --timeout 10m \
                --base-port \$BASE_PORT \
                --output-dir "\$OUTPUT_DIR" \
                --cleanup 2>&1 | tee "\$LOG_FILE"
            
            TEST_RESULT=\$?
            
            # 检查测试结果
            if grep -q '"status": "passed"' "\$OUTPUT_DIR/test-results.json" 2>/dev/null || grep -q "✅.*测试通过\|status.*passed" "\$LOG_FILE" 2>/dev/null; then
                echo "✅ \$template 测试通过"
                echo "\$template:passed" >> "\$OUTPUT_DIR/passed.txt"
                PASSED=\$((PASSED + 1))
            elif grep -q '"status": "skipped"' "\$OUTPUT_DIR/test-results.json" 2>/dev/null || grep -q "skipped\|跳过" "\$LOG_FILE" 2>/dev/null; then
                echo "⏭️  \$template 被跳过"
                echo "\$template:skipped" >> "\$OUTPUT_DIR/skipped.txt"
                SKIPPED=\$((SKIPPED + 1))
            else
                echo "❌ \$template 测试失败"
                echo "\$template:failed" >> "\$OUTPUT_DIR/failed.txt"
                FAILED=\$((FAILED + 1))
                # 记录失败原因
                echo "失败原因:" >> "\$OUTPUT_DIR/failed.txt"
                tail -10 "\$LOG_FILE" | grep -E "error|Error|ERROR|failed|Failed|FAILED" | head -3 >> "\$OUTPUT_DIR/failed.txt" || true
                echo "---" >> "\$OUTPUT_DIR/failed.txt"
            fi
            
            BASE_PORT=\$((BASE_PORT + 1))
            sleep 2  # 短暂休息
        done < "\$BATCH_FILE"
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📊 批次 \$batch 测试统计"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "总模板数: \$TEMPLATE_COUNT"
        echo "✅ 通过: \$PASSED"
        echo "❌ 失败: \$FAILED"
        echo "⏭️  跳过: \$SKIPPED"
        echo "✅ 批次 \$batch 测试完成"
    done
else
    echo "🧪 测试批次 $BATCH_NUM..."
    BATCH_FILE="$SSLCAT_DIR/scripts/batch-${BATCH_NUM}-templates.txt"
    
    if [ ! -f "\$BATCH_FILE" ]; then
        echo "❌ 批次文件不存在: \$BATCH_FILE"
        exit 1
    fi
    
    BASE_PORT=\$((20000 + ($BATCH_NUM - 1) * 100))
    OUTPUT_DIR="$TEST_DIR/results/batch-${BATCH_NUM}"
    
    echo "📋 批次文件: \$BATCH_FILE"
    echo "🔌 基础端口: \$BASE_PORT"
    echo "📁 输出目录: \$OUTPUT_DIR"
    
    # 逐个测试模板
    TEMPLATE_COUNT=\$(wc -l < "\$BATCH_FILE")
    CURRENT=0
    PASSED=0
    FAILED=0
    SKIPPED=0
    
    # 初始化结果文件
    mkdir -p "\$OUTPUT_DIR"
    echo "[]" > "\$OUTPUT_DIR/test-results.json"
    > "\$OUTPUT_DIR/passed.txt"
    > "\$OUTPUT_DIR/failed.txt"
    > "\$OUTPUT_DIR/skipped.txt"
    
    while IFS= read -r template; do
        [ -z "\$template" ] && continue
        CURRENT=\$((CURRENT + 1))
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🧪 测试模板 [\$CURRENT/\$TEMPLATE_COUNT]: \$template"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        LOG_FILE="$TEST_DIR/results/batch-${BATCH_NUM}-\${template}.log"
        
        ./test-templates \
            --template "\$template" \
            --templates-dir ../../internal/runner/templates/builtin \
            --parallel 1 \
            --timeout 10m \
            --base-port \$BASE_PORT \
            --output-dir "\$OUTPUT_DIR" \
            --cleanup 2>&1 | tee "\$LOG_FILE"
        
        TEST_RESULT=\$?
        
        # 检查测试结果
        if grep -q '"status": "passed"' "\$OUTPUT_DIR/test-results.json" 2>/dev/null || grep -q "✅.*测试通过\|status.*passed" "\$LOG_FILE" 2>/dev/null; then
            echo "✅ \$template 测试通过"
            echo "\$template:passed" >> "\$OUTPUT_DIR/passed.txt"
            PASSED=\$((PASSED + 1))
        elif grep -q '"status": "skipped"' "\$OUTPUT_DIR/test-results.json" 2>/dev/null || grep -q "skipped\|跳过\|镜像不存在\|rate limit" "\$LOG_FILE" 2>/dev/null; then
            echo "⏭️  \$template 被跳过"
            echo "\$template:skipped" >> "\$OUTPUT_DIR/skipped.txt"
            SKIPPED=\$((SKIPPED + 1))
            # 记录跳过原因
            echo "跳过原因:" >> "\$OUTPUT_DIR/skipped.txt"
            grep -E "镜像不存在|rate limit|toomanyrequests|denied|manifest unknown" "\$LOG_FILE" | head -2 >> "\$OUTPUT_DIR/skipped.txt" || true
            echo "---" >> "\$OUTPUT_DIR/skipped.txt"
        else
            echo "❌ \$template 测试失败"
            echo "\$template:failed" >> "\$OUTPUT_DIR/failed.txt"
            FAILED=\$((FAILED + 1))
            # 记录失败原因
            echo "失败原因:" >> "\$OUTPUT_DIR/failed.txt"
            tail -15 "\$LOG_FILE" | grep -E "error|Error|ERROR|failed|Failed|FAILED|timeout|Timeout|端口|port|connection|refused" | head -5 >> "\$OUTPUT_DIR/failed.txt" || tail -5 "\$LOG_FILE" >> "\$OUTPUT_DIR/failed.txt"
            echo "---" >> "\$OUTPUT_DIR/failed.txt"
        fi
        
        BASE_PORT=\$((BASE_PORT + 1))
        sleep 2  # 短暂休息，避免资源竞争
    done < "\$BATCH_FILE"
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 批次 $BATCH_NUM 测试统计"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "总模板数: \$TEMPLATE_COUNT"
    echo "✅ 通过: \$PASSED"
    echo "❌ 失败: \$FAILED"
    echo "⏭️  跳过: \$SKIPPED"
    
    echo ""
    echo "✅ 批次 $BATCH_NUM 测试完成"
    echo "📄 结果目录: \$OUTPUT_DIR"
fi

echo ""
echo "📊 测试完成"
echo "📁 结果目录: $TEST_DIR/results"

ENDSSH

SSH_EXIT_CODE=$?

if [ $SSH_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ 测试执行完成${NC}"
    
    # 下载测试结果
    echo -e "${YELLOW}📥 下载测试结果...${NC}"
    mkdir -p "$PROJECT_DIR/test-results"
    
    if [ "$BATCH_NUM" = "all" ]; then
        for batch in 1 2 3 4 5 6; do
            scp -r "$SERVER:$TEST_DIR/results/batch-\${batch}" "$PROJECT_DIR/test-results/" 2>/dev/null || true
        done
    else
        scp -r "$SERVER:$TEST_DIR/results/batch-${BATCH_NUM}" "$PROJECT_DIR/test-results/" 2>/dev/null || true
        scp "$SERVER:$TEST_DIR/results/batch-${BATCH_NUM}-*.log" "$PROJECT_DIR/test-results/" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ 测试结果已下载到: $PROJECT_DIR/test-results/${NC}"
else
    echo -e "${RED}❌ 测试执行失败（退出码: $SSH_EXIT_CODE）${NC}"
    exit $SSH_EXIT_CODE
fi

