#!/bin/bash

# 运行模板测试脚本
# 在 sg2.shifen.de 上执行模板测试

set -e

SERVER="root@sg2.shifen.de"
SSLCAT_DIR="/opt/sslcat"
TEST_DIR="/opt/sslcat-test"
PRIORITY="${1:-all}"  # all, high, medium, low

echo "🧪 开始运行模板测试 (优先级: $PRIORITY)..."

# 同步代码到服务器（如果需要）
echo "📥 同步代码到服务器..."
rsync -avz --exclude 'node_modules' --exclude '.git' \
    ./ $SERVER:$SSLCAT_DIR/ || {
    echo "⚠️  rsync 失败，使用现有代码"
}

# 在服务器上执行测试
ssh $SERVER bash << ENDSSH
set -e

cd $SSLCAT_DIR

echo "🔧 设置环境变量..."
export PATH=\$PATH:/usr/local/go/bin
export GOPATH=/opt/go
export GOBIN=\$GOPATH/bin

echo "📦 编译测试工具..."
cd tools/test-templates
go mod tidy
go build -o test-templates .

echo "🧪 开始测试..."

# 创建输出目录
mkdir -p $TEST_DIR/results

# 根据优先级运行测试
if [ "$PRIORITY" = "all" ]; then
    echo "测试所有优先级的模板..."
    ./test-templates \
        --templates-dir ../../internal/runner/templates/builtin \
        --parallel 2 \
        --timeout 10m \
        --base-port 20000 \
        --output-dir $TEST_DIR/results \
        --cleanup
else
    echo "测试 $PRIORITY 优先级的模板..."
    ./test-templates \
        --templates-dir ../../internal/runner/templates/builtin \
        --priority $PRIORITY \
        --parallel 2 \
        --timeout 10m \
        --base-port 20000 \
        --output-dir $TEST_DIR/results \
        --cleanup
fi

echo "✅ 测试完成"
echo "📄 结果文件: $TEST_DIR/results/test-results.json"

ENDSSH

# 下载测试结果
echo "📥 下载测试结果..."
scp $SERVER:$TEST_DIR/results/test-results.json ./test-results.json || {
    echo "⚠️  下载测试结果失败"
}

echo "✅ 测试完成！"
echo "📄 测试结果已保存到: ./test-results.json"

