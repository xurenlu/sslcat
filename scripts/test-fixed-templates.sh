#!/bin/bash

# 测试已修复的6个模板

set +e

SERVER="root@47.82.4.54"
SSLCAT_DIR="/opt/sslcat"

TEMPLATES=(
    "bark"
    "coqui-tts"
    "jitsi-meet"
    "sentiment-monitor"
    "whisper"
    "zipkin"
)

echo "🧪 测试已修复的6个模板"
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
echo "开始测试6个已修复的模板..."
echo ""

PASSED=0
FAILED=0

for template in bark coqui-tts jitsi-meet sentiment-monitor whisper zipkin; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🧪 测试: $template"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    ./test-templates \
        --template "$template" \
        --templates-dir ../../internal/runner/templates/builtin \
        --parallel 1 \
        --timeout 5m \
        --base-port 25000 \
        --output-dir /tmp/test-fixed \
        --cleanup 2>&1 | tail -30
    
    # 检查是否通过
    if grep -q '"status": "passed"' /tmp/test-fixed/test-results.json 2>/dev/null; then
        echo "✅ $template 测试通过"
        PASSED=$((PASSED + 1))
    else
        echo "❌ $template 测试失败或跳过"
        FAILED=$((FAILED + 1))
    fi
    
    echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 测试统计"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "总模板数: 6"
echo "✅ 通过: $PASSED"
echo "❌ 失败/跳过: $FAILED"
echo ""

ENDSSH

echo "✅ 测试完成"

