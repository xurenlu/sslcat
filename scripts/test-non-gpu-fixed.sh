#!/bin/bash

# 测试不需要GPU的3个已修复模板

set +e

SERVER="root@47.82.4.54"
SSLCAT_DIR="/opt/sslcat"

echo "🧪 测试不需要GPU的3个已修复模板"
echo "服务器: $SERVER"
echo ""

# 同步代码
echo "📥 同步代码到服务器..."
rsync -avz --exclude 'node_modules' --exclude '.git' --exclude 'dist' --exclude 'build' \
    . "$SERVER:$SSLCAT_DIR/" 2>&1 | tail -5

# 在服务器上执行测试
ssh $SERVER bash << 'ENDSSH'
set +e

cd /opt/sslcat
export PATH=$PATH:/usr/local/go/bin

cd tools/test-templates

if [ ! -f "./test-templates" ]; then
    echo "编译测试工具..."
    go build -o test-templates . 2>&1 | tail -5
fi

echo ""
echo "开始测试3个不需要GPU的已修复模板..."
echo ""

PASSED=0
FAILED=0
SKIPPED=0

for template in jitsi-meet sentiment-monitor zipkin; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🧪 测试: $template"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    ./test-templates \
        --template "$template" \
        --templates-dir ../../internal/runner/templates/builtin \
        --parallel 1 \
        --timeout 5m \
        --base-port 25000 \
        --output-dir /tmp/test-fixed-$template \
        --cleanup
    
    # 检查是否通过
    if grep -q '"status": "passed"' /tmp/test-fixed-$template/test-results.json 2>/dev/null; then
        echo "✅ $template 测试通过"
        PASSED=$((PASSED + 1))
    elif grep -q '"status": "skipped"' /tmp/test-fixed-$template/test-results.json 2>/dev/null; then
        echo "⏭️  $template 被跳过"
        SKIPPED=$((SKIPPED + 1))
    else
        echo "❌ $template 测试失败"
        FAILED=$((FAILED + 1))
    fi
    
    echo ""
    sleep 3
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 测试统计"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "总模板数: 3"
echo "✅ 通过: $PASSED"
echo "❌ 失败: $FAILED"
echo "⏭️  跳过: $SKIPPED"
echo ""

ENDSSH

echo "✅ 测试完成"

